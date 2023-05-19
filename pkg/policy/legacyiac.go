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

	"github.com/open-policy-agent/opa/ast"

	"github.com/snyk/policy-engine/pkg/input"
	"github.com/snyk/policy-engine/pkg/logging"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/policy/legacyiac"
	"github.com/snyk/policy-engine/pkg/rego"
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
		inputValue, err := ast.InterfaceToValue(input.Raw())
		if err != nil {
			logger.Error(ctx, "Failed to prepare input")
			return p.errorOutput(err)
		}
		builtins := NewBuiltins(options.Input, options.ResourcesResolver)
		strictBuiltinErrors := false
		query := rego.Query{
			Builtins:            builtins.Implementations(),
			Query:               p.judgementRule.queryElem(),
			Input:               inputValue,
			StrictBuiltinErrors: &strictBuiltinErrors,
			Timeout:             options.Timeout,
		}
		processor := legacyIaCProcessor{
			pkg:                      p.pkg,
			input:                    input,
			defaultResourceNamespace: defaultResourceNamespace,
			inputType:                options.Input.InputType,
			resultsByRuleID:          map[string]models.RuleResults{},
		}
		if err := options.RegoState.Query(
			ctx,
			query,
			func(val ast.Value) error {
				return processor.Process(val)
			},
		); err != nil {
			logger.WithError(err).Error(ctx, "Failed to evaluate query")
			return p.errorOutput(err)
		}
		ruleResults = append(ruleResults, processor.Results()...)
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

type legacyIaCProcessor struct {
	pkg                      string
	input                    legacyiac.Input
	defaultResourceNamespace string
	inputType                string

	resultsByRuleID map[string]models.RuleResults
}

func (r *legacyIaCProcessor) Process(val ast.Value) error {
	var ir legacyIaCResult
	if err := rego.Bind(val, &ir); err != nil {
		return err
	}

	id := ir.PublicID
	ruleResults, ok := r.resultsByRuleID[id]
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
			Package_:    r.pkg,
		}
	}
	result, err := ir.toRuleResult(r.input, r.defaultResourceNamespace, r.inputType)
	if err != nil {
		return err
	}
	ruleResults.Results = append(ruleResults.Results, result)
	r.resultsByRuleID[id] = ruleResults
	return nil
}

func (r *legacyIaCProcessor) Results() []models.RuleResults {
	out := []models.RuleResults{}
	for _, r := range r.resultsByRuleID {
		out = append(out, r)
	}
	return out
}

type legacyIaCRemediation struct {
	Default     string
	ByInputType map[string]string
}

func parseLegacyIaCRemediation(val interface{}) (*legacyIaCRemediation, error) {
	if str, ok := val.(string); ok {
		return &legacyIaCRemediation{Default: str}, nil
	} else if obj, ok := val.(map[string]interface{}); ok {
		byInputType := map[string]string{}
		for k, v := range obj {
			if str, ok := v.(string); ok {
				byInputType[k] = str
			} else {
				return nil, fmt.Errorf("remediation: expected string")
			}
		}
		return &legacyIaCRemediation{ByInputType: byInputType}, nil
	} else {
		return nil, fmt.Errorf("remediation: expected string or object")
	}
}

type legacyIaCResult struct {
	PublicID    string      `rego:"publicId"`
	Title       string      `rego:"title"`
	Severity    string      `rego:"severity"`
	Msg         string      `rego:"msg"`
	Issue       string      `rego:"issue"`
	Impact      string      `rego:"impact"`
	Remediation interface{} `rego:"remediation"`
	References  []string    `rego:"references"`
}

func (r *legacyIaCResult) toRuleResult(
	input legacyiac.Input,
	defaultResourceNamespace string,
	inputType string,
) (models.RuleResult, error) {
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

	remediation, err := parseLegacyIaCRemediation(result.Remediation)
	if err != nil {
		return result, err
	}
	if remediation.Default != "" {
		result.Remediation = remediation.Default
	} else if key, ok := remediationKeys[inputType]; ok {
		result.Remediation = remediation.ByInputType[key]
	}

	return result, nil
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
