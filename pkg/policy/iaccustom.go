package policy

import (
	"context"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/rego"
	"github.com/snyk/unified-policy-engine/pkg/logging"
	"github.com/snyk/unified-policy-engine/pkg/models"
)

// This file contains code for backwards compatibility with Snyk IaC custom rules

type IaCCustomPolicy struct {
	*BasePolicy
}

func (p *IaCCustomPolicy) Eval(
	ctx context.Context,
	options EvalOptions,
) ([]models.RuleResults, error) {
	logger := options.Logger
	if logger == nil {
		logger = logging.DefaultLogger
	}
	logger = logger.WithField(logging.POLICY_TYPE, "iac_custom")
	input := toIaCCustomInput(options.Input)
	opts := append(
		options.RegoOptions,
		rego.Query(p.judgementRule.query()),
		rego.Input(input),
	)
	builtins := NewBuiltins(options.Input)
	opts = append(opts, builtins.Rego()...)
	query, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		logger.Error(ctx, "Failed to prepare for eval")
		return nil, err
	}
	resultSet, err := query.Eval(ctx)
	if err != nil {
		logger.Error(ctx, "Failed to evaluate query")
		return nil, err
	}
	ir := iacResults{}
	if err := unmarshalResultSet(resultSet, &ir); err != nil {
		logger.Error(ctx, "Failed to unmarshal result set")
		return nil, err
	}
	return ir.toRuleResults(), nil
}

type iacResults []*iacResult

func (r iacResults) toRuleResults() []models.RuleResults {
	resultsByRuleID := map[string]models.RuleResults{}
	for _, ir := range r {
		id := ir.PublicID
		ruleResults, ok := resultsByRuleID[id]
		if !ok {
			ruleResults = models.RuleResults{
				Id:          id,
				Title:       ir.Title,
				Description: ir.Issue,                          // TODO: Maybe this should be a combination of both impact and issue?
				References:  strings.Join(ir.References, "\n"), // TODO: How do we want to transform these?
			}
		}
		ruleResults.Results = append(ruleResults.Results, *ir.toRuleResult())
		resultsByRuleID[id] = ruleResults
	}
	output := make([]models.RuleResults, 0, len(resultsByRuleID))
	for _, r := range resultsByRuleID {
		output = append(output, r)
	}
	return output
}

type iacResult struct {
	PublicID    string   `json:"publicId"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Msg         string   `json:"msg"`
	Issue       string   `json:"issue"`
	Impact      string   `json:"impact"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references"`
}

func (r *iacResult) toRuleResult() *models.RuleResult {
	result := parseMsg(r.Msg)
	result.Passed = false
	result.Remediation = r.Remediation
	result.Severity = r.Severity
	return result
}

type parseMsgState int

const (
	initial parseMsgState = iota
	inInput
	inResource
	inResourceType
	inAttributePath
)

func parseMsg(msg string) *models.RuleResult {
	path := []interface{}{}
	buf := []rune{}
	var resourceID string
	var resourceType string
	var state parseMsgState
	var inBracket bool
	consumeBuf := func() {
		s := string(buf)
		switch state {
		case initial:
			if s == "input" {
				state = inInput
			}
		case inInput:
			if s == "resource" {
				state = inResource
			}
		case inResource:
			resourceType = s
			state = inResourceType
		case inResourceType:
			resourceID = s
			state = inAttributePath
		case inAttributePath:
			if s == "" {
				break
			}
			if i, err := strconv.Atoi(s); err == nil {
				path = append(path, i)
			} else {
				path = append(path, s)
			}
		}
		buf = []rune{}
	}
	for _, char := range msg {
		switch char {
		case '.':
			if !inBracket {
				consumeBuf()
			} else {
				buf = append(buf, char)
			}
		case '[':
			consumeBuf()
			inBracket = true
		case ']':
			consumeBuf()
			inBracket = false
		default:
			buf = append(buf, char)
		}
	}
	consumeBuf()
	result := &models.RuleResult{
		ResourceId:   resourceID,
		ResourceType: resourceType,
	}
	if resourceID != "" {
		resource := models.RuleResultResource{}
		if len(path) > 0 {
			resource.Attributes = []models.RuleResultResourceAttribute{
				{
					Path: path,
				},
			}
		}
		result.Resources = map[string]models.RuleResultResource{
			resourceID: resource,
		}
	}
	return result
}

func toIaCCustomInput(state *models.State) map[string]map[string]map[string]interface{} {
	inputResource := map[string]map[string]interface{}{}
	for rt, resources := range state.Resources {
		inputResourceType := map[string]interface{}{}
		for name, r := range resources {
			inputResourceType[name] = r.Attributes
		}
		inputResource[rt] = inputResourceType
	}
	return map[string]map[string]map[string]interface{}{
		"resource": inputResource,
	}
}
