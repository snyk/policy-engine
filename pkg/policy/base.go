// Copyright 2022 Snyk Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/snyk/policy-engine/pkg/input"
	"github.com/snyk/policy-engine/pkg/logging"
	"github.com/snyk/policy-engine/pkg/models"
)

// Constants used to determine a policy's type.
var judgementRuleNames = map[string]bool{
	"deny":   true,
	"allow":  true,
	"policy": true,
}

var metadataRuleNames = map[string]bool{
	"metadata":          true,
	"__rego__metadoc__": true,
}

const resourcesRuleName = "resources"
const resourceTypeRuleName = "resource_type"
const inputTypeRuleName = "input_type"
const multipleResourceType = "MULTIPLE"

// SupportedInputTypes contains all of the input types that this package officially
// supports.
var SupportedInputTypes = input.Types{
	input.Any,
	input.Arm,
	input.CloudFormation,
	input.CloudScan,
	input.Kubernetes,
	input.TerraformHCL,
	input.TerraformPlan,
	input.Terraform,
}

type EvalOptions struct {
	RegoOptions       []func(*rego.Rego)
	Input             *models.State
	InputValue        ast.Value
	Logger            logging.Logger
	ResourcesResolver ResourcesResolver
}

// Policy is an interface that supports all of the ways we want to interact
// with policies.
type Policy interface {
	Package() string
	Metadata(ctx context.Context, options []func(*rego.Rego)) (Metadata, error)
	ID(ctx context.Context, options []func(*rego.Rego)) (string, error)
	Eval(ctx context.Context, options EvalOptions) ([]models.RuleResults, error)
	InputType() string
	InputTypeMatches(inputType string) bool
}

type ruleInfo struct {
	name  string
	key   string
	rules []*ast.Rule
	value string
}

func (i *ruleInfo) add(r *ast.Rule) error {
	name := r.Head.Name.String()
	if i.name != "" && name != i.name {
		return fmt.Errorf("Mismatched rule names: %s and %s", name, i.name)
	}
	if i.name == "" {
		i.name = name
	}
	i.rules = append(i.rules, r)
	if !r.Default {
		if r.Head.Key != nil {
			if k, ok := r.Head.Key.Value.(ast.Var); ok {
				i.key = string(k)
			}
		}
		if r.Head.Value != nil {
			if v, ok := r.Head.Value.Value.(ast.String); ok {
				i.value = string(v)
			}
		}
	}
	return nil
}

func (i *ruleInfo) query() string {
	if len(i.rules) < 1 {
		return ""
	}
	return i.rules[0].Path().String()
}

func (i *ruleInfo) hasKey() bool {
	return i.key != ""
}

// remediationKeys is a map of input type name to the key that's used in the remediation
// map in metadata
var remediationKeys = map[string]string{
	input.Arm.Name:            "arm",
	input.CloudFormation.Name: "cloudformation",
	input.CloudScan.Name:      "console",
	input.Kubernetes.Name:     "k8s",
	input.TerraformHCL.Name:   "terraform",
	input.TerraformPlan.Name:  "terraform",
}

type Metadata struct {
	ID           string                         `json:"id"`
	Title        string                         `json:"title"`
	Description  string                         `json:"description"`
	Platform     []string                       `json:"platform"`
	Remediation  map[string]string              `json:"remediation"`
	References   map[string][]MetadataReference `json:"references"`
	Category     string                         `json:"category"`
	Labels       []string                       `json:"labels,omitempty"`
	ServiceGroup string                         `json:"service_group"`
	Controls     map[string]map[string][]string `json:"controls"`
	Severity     string                         `json:"severity"`
	Product      []string                       `json:"product"`
}

func (m Metadata) RemediationFor(inputType string) string {
	key, ok := remediationKeys[inputType]
	if !ok {
		return ""
	}
	return m.Remediation[key]
}

type MetadataReference struct {
	URL   string `json:"url"`
	Title string `json:"title,omitempty"`
}

func (m Metadata) ReferencesFor(inputType string) []MetadataReference {
	output := []MetadataReference{}

	if refs, ok := m.References["general"]; ok {
		output = append(output, refs...)
	}

	if key, ok := remediationKeys[inputType]; ok {
		if refs, ok := m.References[key]; ok {
			output = append(output, refs...)
		}
	}

	return output
}

// Propagate static metadata to rule results.
func (m Metadata) copyToRuleResults(inputType string, output *models.RuleResults) {
	output.Id = m.ID
	output.Title = m.Title
	output.Description = m.Description
	output.Platform = m.Platform
	output.Category = m.Category
	output.Labels = m.Labels
	output.ServiceGroup = m.ServiceGroup
	output.Controls = m.Controls

	output.References = []models.RuleResultsReference{}
	for _, ref := range m.ReferencesFor(inputType) {
		output.References = append(output.References, models.RuleResultsReference{
			Url:   ref.URL,
			Title: ref.Title,
		})
	}
}

// BasePolicy implements functionality that is shared between different concrete
// Policy implementations.
type BasePolicy struct {
	pkg              string
	resourceType     string
	inputType        *input.Type
	judgementRule    ruleInfo
	metadataRule     ruleInfo
	resourcesRule    ruleInfo
	inputTypeRule    ruleInfo
	resourceTypeRule ruleInfo
	cachedMetadata   *Metadata
}

// ModuleSet is a set of Modules that all share the same package name
type ModuleSet struct {
	Path    ast.Ref
	Modules []*ast.Module
}

// NewBasePolicy constructs a new BasePolicy. It will return an error if the Module
// does not contain a recognized Judgement.
func NewBasePolicy(moduleSet ModuleSet) (*BasePolicy, error) {
	pkg := moduleSet.Path.String()
	judgementRule := ruleInfo{}
	metadataRule := ruleInfo{}
	resourcesRule := ruleInfo{}
	inputTypeRule := ruleInfo{}
	resourceTypeRule := ruleInfo{}
	for _, module := range moduleSet.Modules {
		for _, r := range module.Rules {
			name := r.Head.Name.String()
			switch name {
			case "allow", "deny", "policy":
				if err := judgementRule.add(r); err != nil {
					return nil, err
				}
			case "metadata", "__rego__metadoc__":
				if err := metadataRule.add(r); err != nil {
					return nil, err
				}
			case "resources":
				if err := resourcesRule.add(r); err != nil {
					return nil, err
				}
			case "input_type":
				if err := inputTypeRule.add(r); err != nil {
					return nil, err
				}
			case "resource_type":
				if err := resourceTypeRule.add(r); err != nil {
					return nil, err
				}
			}
		}
	}
	if judgementRule.name == "" {
		return nil, nil
	}
	resourceType := resourceTypeRule.value
	if resourceType == "" {
		resourceType = multipleResourceType
	}
	var inputType *input.Type
	if inputTypeRule.value != "" {
		// TODO: This code currently handles unknown input types by creating a new input
		// type, which is one way to support arbitrary input types. Do we want to
		// consider this case an error instead?
		inputType, _ = SupportedInputTypes.FromString(inputTypeRule.value)
		if inputType == nil {
			inputType = &input.Type{
				Name: inputTypeRule.value,
			}
		}
	} else {
		inputType = input.Any
	}
	return &BasePolicy{
		pkg:              pkg,
		resourceType:     resourceType,
		inputType:        inputType,
		judgementRule:    judgementRule,
		metadataRule:     metadataRule,
		resourcesRule:    resourcesRule,
		inputTypeRule:    inputTypeRule,
		resourceTypeRule: resourceTypeRule,
	}, nil
}

// Package returns the policy's package
func (p *BasePolicy) Package() string {
	return p.pkg
}

func (p *BasePolicy) InputType() string {
	return p.inputType.Name
}

func (p *BasePolicy) InputTypeMatches(inputType string) bool {
	return p.inputType.Matches(inputType)
}

func (p *BasePolicy) Metadata(
	ctx context.Context,
	options []func(*rego.Rego),
) (Metadata, error) {
	if p.cachedMetadata != nil {
		return *p.cachedMetadata, nil
	}
	m := Metadata{}
	if p.metadataRule.name == "" {
		p.cachedMetadata = &m
		return m, nil
	}
	options = append(
		options,
		rego.Query(p.metadataRule.query()),
	)
	query, err := rego.New(options...).PrepareForEval(ctx)
	if err != nil {
		return m, err
	}
	results, err := query.Eval(ctx)
	if err != nil {
		return m, err
	}
	switch p.metadataRule.name {
	case "metadata":
		if err := unmarshalResultSet(results, &m); err != nil {
			return m, err
		}
	case "__rego__metadoc__":
		d := metadoc{}
		if err := unmarshalResultSet(results, &d); err != nil {
			return m, err
		}
		m = Metadata{
			ID:          d.Id,
			Title:       d.Title,
			Description: d.Description,
		}
		if d.Custom != nil {
			// It's not necessary to process controls here, because this path is only
			// for backwards compatibility with custom rules.
			m.Severity = d.Custom.Severity
		}
	default:
		return m, fmt.Errorf("Unrecognized metadata rule: %s", p.metadataRule.name)
	}
	p.cachedMetadata = &m
	return m, nil
}

func (p *BasePolicy) ID(
	ctx context.Context,
	options []func(*rego.Rego),
) (string, error) {
	metadata, err := p.Metadata(ctx, options)
	if err != nil {
		return "", err
	}
	return metadata.ID, nil
}

func (p *BasePolicy) resources(
	ctx context.Context,
	options []func(*rego.Rego),
) (map[string]*ruleResultBuilder, error) {
	r := map[string]*ruleResultBuilder{} // By correlation
	if p.resourcesRule.name == "" {
		return r, nil
	}
	options = append(
		options,
		rego.Query(p.resourcesRule.query()),
	)
	query, err := rego.New(options...).PrepareForEval(ctx)
	if err != nil {
		return r, err
	}
	resultSet, err := query.Eval(ctx)
	if err != nil {
		return r, err
	}
	results := []resourcesResult{}
	if err := unmarshalResultSet(resultSet, &results); err != nil {
		return r, err
	}
	for _, result := range results {
		if result.Resource == nil && result.PrimaryResource == nil {
			continue
		}

		correlation := result.GetCorrelation()
		if _, ok := r[correlation]; !ok {
			r[correlation] = newRuleResultBuilder()
		}
		if result.Resource != nil {
			r[correlation].addResource(result.Resource.Key())
		}
		if result.PrimaryResource != nil {
			r[correlation].setPrimaryResource(result.PrimaryResource.Key())
		}
		for _, attr := range result.Attributes {
			r[correlation].addResourceAttribute(result.GetResource().Key(), attr)
		}
	}
	return r, nil
}

// unmarshalResultSet is a small utility function to extract the correct types out of
// a ResultSet.
func unmarshalResultSet(resultSet rego.ResultSet, v interface{}) error {
	if len(resultSet) < 1 {
		return nil
	}
	if len(resultSet[0].Expressions) < 1 {
		return nil
	}
	data, err := json.Marshal(resultSet[0].Expressions[0].Value)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

type policyResultResource struct {
	ID           string `json:"id"`
	ResourceType string `json:"_type"`
	Namespace    string `json:"_namespace"`
}

// This struct represents the common return format for the policy engine policies.
type policyResult struct {
	Message      string                `json:"message"`
	Resource     *policyResultResource `json:"resource"`
	ResourceType string                `json:"resource_type"`
	Remediation  string                `json:"remediation"`
	Severity     string                `json:"severity"`
	Attributes   [][]interface{}       `json:"attributes"`
	Correlation  string                `json:"correlation"`

	// Backwards compatibility
	FugueValid             bool   `json:"valid"`
	FugueID                string `json:"id"`
	FugueResourceType      string `json:"type"`
	FugueResourceNamespace string `json:"namespace"`
}

type resourcesResult struct {
	Resource        *policyResultResource `json:"resource"`
	PrimaryResource *policyResultResource `json:"primary_resource"`
	Attributes      [][]interface{}       `json:"attributes"`
	Correlation     string                `json:"correlation"`
}

// Helper for unique resource identifiers, meant to be used as key in a `map`.
type ResourceKey struct {
	Namespace string
	Type      string
	ID        string
}

func RuleResultResourceKey(r models.RuleResultResource) ResourceKey {
	return ResourceKey{
		Namespace: r.Namespace,
		Type:      r.Type,
		ID:        r.Id,
	}
}

func (result policyResult) GetCorrelation() string {
	if result.Correlation != "" {
		return result.Correlation
	} else if result.Resource != nil {
		return result.Resource.Correlation()
	} else {
		return ""
	}
}

func (k ResourceKey) Correlation() string {
	escape := func(s string) string {
		return strings.ReplaceAll(s, "$", "$$")
	}
	return fmt.Sprintf("%s$%s$%s", escape(k.Namespace), escape(k.Type), escape(k.ID))
}

func (resource *policyResultResource) Key() ResourceKey {
	// NOTE: Why is 'ResourceType' a seperate thing from 'policyResultResource'?
	// The idea is that the latter represents all the data that can be
	// returned from Rego rules (and this can be extended in the future),
	// whereas the former is just a way to uniquely identify resources.
	return ResourceKey{
		Namespace: resource.Namespace,
		Type:      resource.ResourceType,
		ID:        resource.ID,
	}
}

func (resource *policyResultResource) Correlation() string {
	return resource.Key().Correlation()
}

func (result resourcesResult) GetResource() *policyResultResource {
	if result.Resource != nil {
		return result.Resource
	} else if result.PrimaryResource != nil {
		return result.PrimaryResource
	} else {
		return nil
	}
}

func (result resourcesResult) GetCorrelation() string {
	if result.Correlation != "" {
		return result.Correlation
	} else if result.PrimaryResource != nil {
		return result.PrimaryResource.Correlation()
	} else if result.Resource != nil {
		return result.Resource.Correlation()
	} else {
		return ""
	}
}
