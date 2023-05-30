// © 2022-2023 Snyk Limited All rights reserved.
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
	"fmt"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/snyk/policy-engine/pkg/input"
	"github.com/snyk/policy-engine/pkg/logging"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/rego"
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
const defaultKind = "vulnerability"

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
	RegoState         *rego.State
	Input             *models.State
	Logger            logging.Logger
	ResourcesResolver ResourcesResolver
	Timeout           time.Duration
}

// Policy is an interface that supports all of the ways we want to interact
// with policies.
type Policy interface {
	Package() string
	Metadata(ctx context.Context, state *rego.State) (Metadata, error)
	ID(ctx context.Context, state *rego.State) (string, error)
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

func (i *ruleInfo) queryElem() string {
	q := i.query()
	if q == "" {
		return q
	} else {
		return q + "[_]"
	}
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
	ID           string                         `json:"id" rego:"id"`
	Title        string                         `json:"title" rego:"title"`
	Description  string                         `json:"description" rego:"description"`
	Platform     []string                       `json:"platform" rego:"platform"`
	Remediation  map[string]string              `json:"remediation" rego:"remediation"`
	References   map[string][]MetadataReference `json:"references" rego:"references"`
	Category     string                         `json:"category" rego:"category"`
	Labels       []string                       `json:"labels,omitempty" rego:"labels"`
	ServiceGroup string                         `json:"service_group" rego:"service_group"`
	Controls     []string                       `json:"controls" rego:"controls"`
	Severity     string                         `json:"severity" rego:"severity"`
	Product      []string                       `json:"product" rego:"product"`
	Kind         string                         `json:"kind" rego:"kind"`
}

func (m Metadata) RemediationFor(inputType string) string {
	key, ok := remediationKeys[inputType]
	if !ok {
		return ""
	}
	return m.Remediation[key]
}

type MetadataReference struct {
	URL   string `json:"url" rego:"url"`
	Title string `json:"title,omitempty" rego:"title"`
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
	output.Kind = m.Kind

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
	state *rego.State,
) (Metadata, error) {
	if p.cachedMetadata != nil {
		return *p.cachedMetadata, nil
	}
	m := Metadata{}
	switch p.metadataRule.name {
	case "metadata":
		if err := state.Query(
			ctx,
			rego.Query{Query: p.metadataRule.query()},
			func(val ast.Value) error {
				err := rego.Bind(val, &m)
				if err != nil {
					return err
				}
				return nil
			},
		); err != nil {
			return m, err
		}

	case "__rego__metadoc__":
		if err := state.Query(
			ctx,
			rego.Query{Query: p.metadataRule.query()},
			func(val ast.Value) error {
				d := metadoc{}
				if err := rego.Bind(val, &d); err != nil {
					return err
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
				return nil
			},
		); err != nil {
			return m, err
		}
	case "": // noop when no metadata rule is defined
	default:
		return m, fmt.Errorf("Unrecognized metadata rule: %s", p.metadataRule.name)
	}
	if m.Kind == "" {
		m.Kind = defaultKind
	}
	p.cachedMetadata = &m
	return m, nil
}

func (p *BasePolicy) ID(
	ctx context.Context,
	state *rego.State,
) (string, error) {
	metadata, err := p.Metadata(ctx, state)
	if err != nil {
		return "", err
	}
	return metadata.ID, nil
}

type policyResultResource struct {
	ID        string `json:"_id" rego:"_id"`
	Type      string `json:"_type" rego:"_type"`
	Namespace string `json:"_namespace" rego:"_namespace"`
}

type policyResultEdge struct {
	Label  string                `json:"label" rego:"label"`
	Source *policyResultResource `json:"source" rego:"source"`
	Target *policyResultResource `json:"target" rego:"target"`
}

// This struct represents the common return format for the policy engine policies.
type policyResult struct {
	Message         string                `json:"message" rego:"message"`
	Resource        *policyResultResource `json:"resource" rego:"resource"`
	PrimaryResource *policyResultResource `json:"primary_resource" rego:"primary_resource"`
	ResourceType    string                `json:"resource_type" rego:"resource_type"`
	Remediation     string                `json:"remediation" rego:"remediation"`
	Severity        string                `json:"severity" rego:"severity"`
	Attributes      [][]interface{}       `json:"attributes" rego:"attributes"`
	Correlation     string                `json:"correlation" rego:"correlation"`
	Graph           []policyResultEdge    `json:"graph" rego:"graph"`

	// Backwards compatibility
	FugueValid             bool   `json:"valid" rego:"valid"`
	FugueID                string `json:"id" rego:"id"`
	FugueResourceType      string `json:"type" rego:"type"`
	FugueResourceNamespace string `json:"namespace" rego:"namespace"`
}

type resourcesResult struct {
	Resource        *policyResultResource `json:"resource" rego:"resource"`
	PrimaryResource *policyResultResource `json:"primary_resource" rego:"primary_resource"`
	Attributes      [][]interface{}       `json:"attributes" rego:"attributes"`
	Correlation     string                `json:"correlation" rego:"correlation"`
	ResourceType    string                `json:"resource_type" rego:"resource_type"`
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

func (result policyResult) GetResource() *policyResultResource {
	if result.Resource != nil {
		return result.Resource
	} else if result.PrimaryResource != nil {
		return result.PrimaryResource
	} else {
		return nil
	}
}

func (result policyResult) GetCorrelation() string {
	if result.Correlation != "" {
		return result.Correlation
	} else if result.ResourceType != "" {
		return result.ResourceType
	} else if result.PrimaryResource != nil {
		return result.PrimaryResource.Correlation()
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

func (l ResourceKey) Less(r ResourceKey) bool {
	if l.Namespace == r.Namespace {
		if l.Type == r.Type {
			if l.ID == r.ID {
				return false
			} else {
				return l.ID < r.ID
			}
		} else {
			return l.Type < r.Type
		}
	} else {
		return l.Namespace < r.Namespace
	}
}

func (resource *policyResultResource) Key() ResourceKey {
	// NOTE: Why is 'ResourceType' a seperate thing from 'policyResultResource'?
	// The idea is that the latter represents all the data that can be
	// returned from Rego rules (and this can be extended in the future),
	// whereas the former is just a way to uniquely identify resources.
	return ResourceKey{
		Namespace: resource.Namespace,
		Type:      resource.Type,
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
	} else if result.ResourceType != "" {
		return result.ResourceType
	} else if result.PrimaryResource != nil {
		return result.PrimaryResource.Correlation()
	} else if result.Resource != nil {
		return result.Resource.Correlation()
	} else {
		return ""
	}
}
