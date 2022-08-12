package policy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
	"github.com/snyk/policy-engine/pkg/input"
	"github.com/snyk/policy-engine/pkg/logging"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/policy/legacyiac"
)

// This file contains code for backwards compatibility with legacy Snyk IaC rules

type LegacyIaCPolicy struct {
	*BasePolicy
}

func (p *LegacyIaCPolicy) Eval(
	ctx context.Context,
	options EvalOptions,
) ([]models.RuleResults, error) {
	logger := options.Logger
	if logger == nil {
		logger = logging.DefaultLogger
	}
	logger = logger.WithField(logging.POLICY_TYPE, "legacy_iac")
	input, err := legacyIaCInput(options.Input)
	if err != nil {
		logger.Error(ctx, "Failed to transform input")
		err = fmt.Errorf("%w: %v", FailedToEvaluateRule, err)
		return p.errorOutput(err)
	}
	resourceNamespace := ""
	if filepath, ok := options.Input.Meta["filepath"].(string); ok {
		resourceNamespace = filepath
	} else {
		logger.Warn(ctx, "No filepath found in meta, using empty namespace")
	}
	opts := append(
		options.RegoOptions,
		rego.Query(p.judgementRule.query()),
		rego.Input(input.Raw()),
		rego.StrictBuiltinErrors(false),
	)
	builtins := NewBuiltins(options.Input, options.ResourcesResolver)
	opts = append(opts, builtins.Rego()...)
	query, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		logger.Error(ctx, "Failed to prepare for eval")
		return p.errorOutput(err)
	}
	resultSet, err := query.Eval(ctx)
	if err != nil {
		logger.Error(ctx, "Failed to evaluate query")
		return p.errorOutput(err)
	}
	ir := legacyIaCResults{}
	if err := unmarshalResultSet(resultSet, &ir); err != nil {
		logger.Error(ctx, "Failed to unmarshal result set")
		return p.errorOutput(err)
	}
	return ir.toRuleResults(p.pkg, input, resourceNamespace, options.Input.InputType), nil
}

func (p *LegacyIaCPolicy) errorOutput(err error) ([]models.RuleResults, error) {
	return []models.RuleResults{
		{
			Package_: p.pkg,
			Errors:   []string{err.Error()},
		},
	}, err
}

type legacyIaCResults []*legacyIaCResult

func (r legacyIaCResults) toRuleResults(pkg string, input legacyiac.Input, resourceNamespace string, inputType string) []models.RuleResults {
	resultsByRuleID := map[string]models.RuleResults{}
	for _, ir := range r {
		id := ir.PublicID
		ruleResults, ok := resultsByRuleID[id]
		if !ok {
			refs := make([]models.RuleResultsReference, len(ir.References))
			for i, r := range ir.References {
				refs[i] = models.RuleResultsReference{Url: r}
			}

			ruleResults = models.RuleResults{
				Id:          id,
				Title:       ir.Title,
				Description: ir.Impact,
				References:  refs,
				Package_:    pkg,
			}
		}
		ruleResults.Results = append(ruleResults.Results, *ir.toRuleResult(input, resourceNamespace, inputType))
		resultsByRuleID[id] = ruleResults
	}
	output := make([]models.RuleResults, 0, len(resultsByRuleID))
	for _, r := range resultsByRuleID {
		output = append(output, r)
	}
	return output
}

type legacyIaCRemediation struct {
	Default     string
	ByInputType map[string]string
}

func (r *legacyIaCRemediation) UnmarshalJSON(data []byte) error {
	var remediationString string
	if err := json.Unmarshal(data, &remediationString); err == nil {
		r.Default = remediationString
		return nil
	}
	var remediationMap map[string]string
	err := json.Unmarshal(data, &remediationMap)
	if err != nil {
		return err
	}
	r.ByInputType = remediationMap
	return nil
}

type legacyIaCResult struct {
	PublicID    string               `json:"publicId"`
	Title       string               `json:"title"`
	Severity    string               `json:"severity"`
	Msg         string               `json:"msg"`
	Issue       string               `json:"issue"`
	Impact      string               `json:"impact"`
	Remediation legacyIaCRemediation `json:"remediation"`
	References  []string             `json:"references"`
}

func (r *legacyIaCResult) toRuleResult(input legacyiac.Input, resourceNamespace string, inputType string) *models.RuleResult {
	parsedMsg := input.ParseMsg(r.Msg)
	builder := newRuleResultBuilder()
	key := ResourceKey{
		ID:        parsedMsg.ResourceID,
		Type:      parsedMsg.ResourceType,
		Namespace: resourceNamespace,
	}
	builder.setPrimaryResource(key)
	if parsedMsg.ResourceID != "" {
		if len(parsedMsg.Path) > 0 {
			builder.addResourceAttribute(key, parsedMsg.Path)
		}
	}
	result := builder.toRuleResult()
	result.Passed = false
	result.Severity = r.Severity

	if r.Remediation.Default != "" {
		result.Remediation = r.Remediation.Default
	} else if key, ok := remediationKeys[inputType]; ok {
		result.Remediation = r.Remediation.ByInputType[key]
	}

	return &result
}

func legacyIaCInput(state *models.State) (legacyiac.Input, error) {
	switch {
	case input.Terraform.Matches(state.InputType):
		return legacyiac.NewTfInput(state), nil
	case input.CloudFormation.Matches(state.InputType):
		return legacyiac.NewCfnInput(state), nil
	case input.Arm.Matches(state.InputType):
		return legacyiac.NewArmInput(state), nil
	default:
		return nil, fmt.Errorf("unsupported input type for this type of rule")
	}
}
