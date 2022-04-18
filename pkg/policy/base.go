package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/snyk/unified-policy-engine/pkg/logging"
	"github.com/snyk/unified-policy-engine/pkg/models"
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
const defaultInputType = "tf"

type EvalOptions struct {
	RegoOptions []func(*rego.Rego)
	Input       *models.State
	Logger      logging.Logger
}

// Policy is an interface that supports all of the ways we want to interact
// with policies.
type Policy interface {
	Package() string
	Metadata(ctx context.Context, options []func(*rego.Rego)) (Metadata, error)
	ID(ctx context.Context, options []func(*rego.Rego)) (string, error)
	Eval(ctx context.Context, options EvalOptions) (*models.RuleResults, error)
	InputType() string
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

type Metadata struct {
	ID           string              `json:"id"`
	Title        string              `json:"title"`
	Description  string              `json:"description"`
	Remediation  map[string]string   `json:"remediation"`
	References   string              `json:"references"` // TODO: Should this be a dict, similar to a bibliography?
	Categories   []string            `json:"categories"`
	ServiceGroup string              `json:"service_group"` // TODO: Should this be a []string?
	Controls     map[string][]string `json:"controls"`
	RuleSets     []string            `json:"rule_sets"`
	Severity     string              `json:"severity"`
}

// BasePolicy implements functionality that is shared between different concrete
// Policy implementations.
type BasePolicy struct {
	module           *ast.Module
	judgementRule    ruleInfo
	metadataRule     ruleInfo
	resourcesRule    ruleInfo
	inputTypeRule    ruleInfo
	resourceTypeRule ruleInfo
	cachedMetadata   *Metadata
}

// NewBasePolicy constructs a new BasePolicy. It will return an error if the Module
// does not contain a recognized Judgement.
func NewBasePolicy(module *ast.Module) (*BasePolicy, error) {
	// ruleInfos := map[string]*RuleInfo{}
	judgement := ruleInfo{}
	metadata := ruleInfo{}
	resources := ruleInfo{}
	inputType := ruleInfo{}
	resourceType := ruleInfo{}
	for _, r := range module.Rules {
		name := r.Head.Name.String()
		switch name {
		case "allow", "deny", "policy":
			if err := judgement.add(r); err != nil {
				return nil, err
			}
		case "metadata", "__rego__metadoc__":
			if err := metadata.add(r); err != nil {
				return nil, err
			}
		case "resources":
			if err := resources.add(r); err != nil {
				return nil, err
			}
		case "input_type":
			if err := inputType.add(r); err != nil {
				return nil, err
			}
		case "resource_type":
			if err := resourceType.add(r); err != nil {
				return nil, err
			}
		}
	}
	if judgement.name == "" {
		return nil, fmt.Errorf(
			"Policy %s did not contain any judgement rules.",
			module.Package.Path.String(),
		)
	}
	return &BasePolicy{
		module:           module,
		judgementRule:    judgement,
		metadataRule:     metadata,
		resourcesRule:    resources,
		inputTypeRule:    inputType,
		resourceTypeRule: resourceType,
	}, nil
}

// Package returns the policy's package
func (p *BasePolicy) Package() string {
	return strings.TrimPrefix(p.module.Package.Path.String(), "data.")
}

func (p *BasePolicy) InputType() string {
	inputType := p.inputTypeRule.value
	if inputType == "" {
		return defaultInputType
	}
	return inputType
}

func (p *BasePolicy) resourceType() string {
	resourceType := p.resourceTypeRule.value
	if resourceType == "" {
		return multipleResourceType
	}
	return resourceType
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
			m.Controls = d.Custom.Controls
			m.RuleSets = d.Custom.Families
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
) (map[string]map[string]models.RuleResultResource, error) {
	r := map[string]map[string]models.RuleResultResource{}
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
		if result.Resource == nil || result.Resource.ID == "" {
			continue
		}
		correlation := result.Correlation
		if correlation == "" {
			correlation = result.Resource.ID
		}
		var attributes []models.RuleResultResourceAttribute
		for _, attr := range result.Attributes {
			attributes = append(attributes, models.RuleResultResourceAttribute{
				Path: attr,
			})
		}
		if _, ok := r[correlation]; !ok {
			r[correlation] = map[string]models.RuleResultResource{}
		}
		r[correlation][result.Resource.ID] = models.RuleResultResource{
			Attributes: attributes,
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
}

// This struct represents the common return format for UPE policies.
type policyResult struct {
	Message      string                `json:"message"`
	Resource     *policyResultResource `json:"resource"`
	ResourceType string                `json:"resource_type"`
	Remediation  string                `json:"remediation"`
	Severity     string                `json:"severity"`
	Attribute    []interface{}         `json:"attribute_path"`

	// Backwards compatibility
	FugueValid        bool   `json:"valid"`
	FugueID           string `json:"id"`
	FugueResourceType string `json:"type"`
}

type resourcesResult struct {
	Resource    *policyResultResource `json:"resource"`
	Attributes  [][]interface{}       `json:"attributes"`
	Correlation string                `json:"correlation"`
}
