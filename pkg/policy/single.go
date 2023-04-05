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
	"sort"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown"

	"github.com/snyk/policy-engine/pkg/logging"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/policy/inferattributes"
	"github.com/snyk/policy-engine/pkg/regobind"
)

// ProcessSingleResultSet functions extract RuleResult models from the ResultSet of
// single-resource type rules.
type ProcessSingleResultSet func(
	resultSet rego.ResultSet,
	resource *models.ResourceState,
	metadata Metadata,
	defaultRemediation string,
) ([]models.RuleResult, error)

// SingleResourcePolicy represents a policy that takes a single resource as input.
type SingleResourcePolicy struct {
	*BasePolicy
	processResultSet     ProcessSingleResultSet
	resultBuilderFactory func(
		resource *models.ResourceState,
		metadata *Metadata,
		defaultRemediation string,
	) ResultBuilder
}

// Eval will evaluate the policy on the given input.
func (p *SingleResourcePolicy) Eval(
	ctx context.Context,
	options EvalOptions,
) ([]models.RuleResults, error) {
	logger := options.Logger
	if logger == nil {
		logger = logging.NopLogger
	}
	logger = logger.WithField(logging.PACKAGE, p.Package()).
		WithField(logging.POLICY_TYPE, "single_resource").
		WithField(logging.JUDGEMENT_NAME, p.judgementRule.name).
		WithField(logging.JUDGEMENT_KEY, p.judgementRule.key).
		WithField(logging.RESOURCE_TYPE, p.resourceType).
		WithField(logging.INPUT_TYPE, p.InputType())
	output := models.RuleResults{}
	output.Package_ = p.pkg

	tracer := inferattributes.NewTracer()
	metadata, err := p.Metadata(ctx, options.RegoState)
	if err != nil {
		logger.Error(ctx, "Failed to query metadata")
		err = fmt.Errorf("%w: %v", FailedToQueryMetadata, err)
		output.Errors = append(output.Errors, err.Error())
		return []models.RuleResults{output}, err
	}
	metadata.copyToRuleResults(options.Input.InputType, &output)
	opts := append(
		options.RegoOptions,
		rego.Query(p.judgementRule.query()),
	)
	query, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		logger.Error(ctx, "Failed to prepare for eval")
		err = fmt.Errorf("%w: %v", FailedToPrepareForEval, err)
		output.Errors = append(output.Errors, err.Error())
		return []models.RuleResults{output}, err
	}
	ruleResults := []models.RuleResult{}
	rt := p.resourceType
	output.ResourceTypes = []string{rt}
	defaultRemediation := metadata.RemediationFor(options.Input.InputType)
	if resources, ok := options.Input.Resources[rt]; ok {
		// Sort resources to produce deterministic output in all cases.
		resourceKeys := []string{}
		for k := range resources {
			resourceKeys = append(resourceKeys, k)
		}
		sort.Strings(resourceKeys)
		for _, rk := range resourceKeys {
			resource := resources[rk]
			logger := logger.WithField(logging.RESOURCE_ID, resource.Id)
			inputDoc, err := resourceStateToRegoInput(resource)
			if err != nil {
				logger.Error(ctx, "Failed to represent resource as input")
				err = fmt.Errorf("%w '%s': %v", FailedToEvaluateResource, resource.Id, err)
				output.Errors = append(output.Errors, err.Error())
				return []models.RuleResults{output}, err
			}
			// TODO: We need a different strategy for unset properties in single-resource rules. The
			// problem is that we lose the top-level location on the term. We might be able to use
			// the fact that the term references `input` instead.
			var results []models.RuleResult
			if p.resultBuilderFactory == nil {
				resultSet, err := query.Eval(ctx, rego.EvalQueryTracer(tracer), rego.EvalParsedInput(inputDoc.Value))
				if err != nil {
					logger.Error(ctx, "Failed to evaluate rule for resource")
					err = fmt.Errorf("%w '%s': %v", FailedToEvaluateResource, resource.Id, err)
					output.Errors = append(output.Errors, err.Error())
					return []models.RuleResults{output}, err
				}
				results, err = p.processResultSet(
					resultSet,
					&resource,
					metadata,
					defaultRemediation,
				)
			} else {
				resultBuilder := p.resultBuilderFactory(
					&resource,
					&metadata,
					defaultRemediation,
				)
				err := options.RegoState.Query(
					ctx,
					&regobind.Query{
						Tracers: []topdown.QueryTracer{tracer},
						Query:   p.judgementRule.query() + "[_]",
						Input:   inputDoc.Value,
					},
					func(val ast.Value) error {
						return resultBuilder.Process(val)
					},
				)
				if err != nil {
					return nil, err
				}
				results = resultBuilder.Results()
			}

			// Fill in paths inferred using the tracer.
			tracer.InferAttributes(results)

			if err != nil {
				logger.Error(ctx, "Failed to process results")
				err = fmt.Errorf("%w: %v", FailedToProcessResults, err)
				output.Errors = append(output.Errors, err.Error())
				return []models.RuleResults{output}, err
			}
			ruleResults = append(ruleResults, results...)
		}
	}
	output.Results = ruleResults
	return []models.RuleResults{output}, nil
}

type ResultBuilder interface {
	Process(ast.Value) error
	Results() []models.RuleResult
}

type SingleDenyResultBuilder struct {
	resource           *models.ResourceState
	metadata           *Metadata
	defaultRemediation string
	results            []models.RuleResult
}

func NewSingleDenyResultBuilder(
	resource *models.ResourceState,
	metadata *Metadata,
	defaultRemediation string,
) ResultBuilder {
	return &SingleDenyResultBuilder{
		resource:           resource,
		metadata:           metadata,
		defaultRemediation: defaultRemediation,
	}
}

func (b *SingleDenyResultBuilder) resourceKey() ResourceKey {
	return ResourceKey{
		ID:        b.resource.Id,
		Type:      b.resource.ResourceType,
		Namespace: b.resource.Namespace,
	}
}

func (b *SingleDenyResultBuilder) Process(val ast.Value) error {
	policyResult := policyResult{}
	if err := regobind.Bind(val, &policyResult); err != nil {
		// It might be a fugue deny[msg] style rule in this case. Try that as a
		// fallback.
		var denyString string
		if strErr := regobind.Bind(val, &denyString); strErr != nil {
			return err
		}
		policyResult.Message = denyString
	}

	rk := b.resourceKey()
	result := newRuleResultBuilder()
	result.setPrimaryResource(rk)
	for _, attr := range policyResult.Attributes {
		result.addResourceAttribute(rk, attr)
	}

	result.messages = append(result.messages, policyResult.Message)
	if policyResult.Severity != "" {
		result.severity = policyResult.Severity
	} else {
		result.severity = b.metadata.Severity
	}
	if policyResult.Remediation != "" {
		result.remediation = policyResult.Remediation
	} else {
		result.remediation = b.defaultRemediation
	}
	b.results = append(b.results, result.toRuleResult())
	return nil
}

func (b *SingleDenyResultBuilder) Results() []models.RuleResult {
	if len(b.results) == 0 {
		// No denies: generate an allow
		result := newRuleResultBuilder()
		result.setPrimaryResource(b.resourceKey())
		result.passed = true
		result.severity = b.metadata.Severity
		return []models.RuleResult{result.toRuleResult()}
	} else {
		return b.results
	}
}
