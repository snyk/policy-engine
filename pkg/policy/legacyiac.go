package policy

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/rego"
	"github.com/snyk/policy-engine/pkg/logging"
	"github.com/snyk/policy-engine/pkg/models"
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
	logger = logger.WithField(logging.POLICY_TYPE, "iac_custom")
	input := toIaCCustomInput(options.Input)
	resourceNamespace := ""
	if filepath, ok := options.Input.Meta["filepath"].(string); ok {
		resourceNamespace = filepath
	} else {
		logger.Warn(ctx, "No filepath found in meta, using empty namespace")
	}
	opts := append(
		options.RegoOptions,
		rego.Query(p.judgementRule.query()),
		rego.Input(input),
	)
	builtins := NewBuiltins(options.Input, options.ResourcesResolver)
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
	ir := legacyIaCResults{}
	if err := unmarshalResultSet(resultSet, &ir); err != nil {
		logger.Error(ctx, "Failed to unmarshal result set")
		return []models.RuleResults{
			{
				Errors: []string{err.Error()},
			},
		}, err
	}
	return ir.toRuleResults(p.pkg, resourceNamespace, options.Input.InputType), nil
}

type legacyIaCResults []*legacyIaCResult

func (r legacyIaCResults) toRuleResults(pkg string, resourceNamespace string, inputType string) []models.RuleResults {
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
				Package_:    pkg,
			}
		}
		ruleResults.Results = append(ruleResults.Results, *ir.toRuleResult(resourceNamespace, inputType))
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

func (r *legacyIaCResult) toRuleResult(resourceNamespace string, inputType string) *models.RuleResult {
	result := parseMsg(r.Msg, resourceNamespace)
	result.Passed = false
	result.Severity = r.Severity

	if r.Remediation.Default != "" {
		result.Remediation = r.Remediation.Default
	} else if key, ok := remediationKeys[inputType]; ok {
		result.Remediation = r.Remediation.ByInputType[key]
	}

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

func parseMsg(msg string, resourceNamespace string) *models.RuleResult {
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
	builder := newRuleResultBuilder()
	key := ResourceKey{
		ID:        resourceID,
		Type:      resourceType,
		Namespace: resourceNamespace,
	}
	builder.setPrimaryResource(key)
	if resourceID != "" {
		if len(path) > 0 {
			builder.addResourceAttribute(key, path)
		}
	}
	result := builder.toRuleResult()
	return &result
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
