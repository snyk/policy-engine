// Copyright 2022-2023 Snyk Ltd
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

func (p *LegacyIaCPolicy) inputType() *input.Type {
	for _, ele := range strings.Split(p.pkg, ".") {
		switch ele {
		case "arm":
			return input.Arm
		case "cloudformation":
			return input.CloudFormation
		case "kubernetes":
			return input.Kubernetes
		case "terraform":
			return input.Terraform
		}
	}
	return p.BasePolicy.inputType
}

func (p *LegacyIaCPolicy) InputType() string {
	return p.inputType().Name
}
func (p *LegacyIaCPolicy) InputTypeMatches(inputType string) bool {
	return p.inputType().Matches(inputType)
}

func (p *LegacyIaCPolicy) Eval(
	ctx context.Context,
	options EvalOptions,
) ([]models.RuleResults, error) {
	logger := options.Logger
	if logger == nil {
		logger = logging.NopLogger
	}
	logger = logger.WithField(logging.POLICY_TYPE, "legacy_iac")
	inputs, err := legacyIaCInput(options.Input)
	if err != nil {
		logger.Error(ctx, "Failed to transform input")
		err = fmt.Errorf("%w: %v", FailedToEvaluateRule, err)
		return p.errorOutput(err)
	}
	defaultResourceNamespace := ""
	if filepath, ok := options.Input.Meta["filepath"].(string); ok {
		defaultResourceNamespace = filepath
	} else {
		logger.Warn(ctx, "No filepath found in meta, using empty namespace")
	}
	ruleResults := []models.RuleResults{}
	for _, input := range inputs {
		raw := input.Raw()
		opts := append(
			options.RegoOptions,
			rego.Query(p.judgementRule.query()),
			rego.Input(raw),
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
		lirs := legacyIaCResults{}
		if err := unmarshalResultSet(resultSet, &lirs); err != nil {
			logger.Error(ctx, "Failed to unmarshal result set")
			return p.errorOutput(err)
		}
		ruleResults = append(
			ruleResults,
			lirs.toRuleResults(p.pkg, input, defaultResourceNamespace, options.Input.InputType)...,
		)
	}
	return ruleResults, nil
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

func (r legacyIaCResults) toRuleResults(pkg string, input legacyiac.Input, defaultResourceNamespace string, inputType string) []models.RuleResults {
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
		ruleResults.Results = append(ruleResults.Results, *ir.toRuleResult(input, defaultResourceNamespace, inputType))
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

func (r *legacyIaCResult) toRuleResult(input legacyiac.Input, defaultResourceNamespace string, inputType string) *models.RuleResult {
	parsedMsg := input.ParseMsg(r.Msg)
	builder := newRuleResultBuilder()
	key := ResourceKey{
		ID:        parsedMsg.ResourceID,
		Type:      parsedMsg.ResourceType,
		Namespace: defaultResourceNamespace,
	}
	if parsedMsg.ResourceNamespace != "" {
		key.Namespace = parsedMsg.ResourceNamespace
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

func legacyIaCInput(state *models.State) ([]legacyiac.Input, error) {
	switch {
	case input.Terraform.Matches(state.InputType):
		return []legacyiac.Input{legacyiac.NewTfInput(state)}, nil
	case input.CloudFormation.Matches(state.InputType):
		return []legacyiac.Input{legacyiac.NewCfnInput(state)}, nil
	case input.Arm.Matches(state.InputType):
		return []legacyiac.Input{legacyiac.NewArmInput(state)}, nil
	case input.Kubernetes.Matches(state.InputType):
		return legacyiac.NewK8sInputs(state), nil
	default:
		return nil, fmt.Errorf("unsupported input type for this type of rule")
	}
}
