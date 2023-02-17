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
	"fmt"
	"sort"

	"github.com/open-policy-agent/opa/rego"

	"github.com/snyk/policy-engine/pkg/logging"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/policy/inferattributes"
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
	processResultSet ProcessSingleResultSet
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
	metadata, err := p.Metadata(ctx, options.RegoOptions)
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
			resultSet, err := query.Eval(ctx, rego.EvalQueryTracer(tracer), rego.EvalParsedInput(inputDoc.Value))
			if err != nil {
				logger.Error(ctx, "Failed to evaluate rule for resource")
				err = fmt.Errorf("%w '%s': %v", FailedToEvaluateResource, resource.Id, err)
				output.Errors = append(output.Errors, err.Error())
				return []models.RuleResults{output}, err
			}
			ruleResult, err := p.processResultSet(
				resultSet,
				&resource,
				metadata,
				defaultRemediation,
			)

			// Fill in paths inferred using the tracer.
			tracer.InferAttributes(ruleResult)

			if err != nil {
				logger.Error(ctx, "Failed to process results")
				err = fmt.Errorf("%w: %v", FailedToProcessResults, err)
				output.Errors = append(output.Errors, err.Error())
				return []models.RuleResults{output}, err
			}
			ruleResults = append(ruleResults, ruleResult...)
		}
	}
	output.Results = ruleResults
	return []models.RuleResults{output}, nil
}

// This is a ProcessSingleResultSet func for the new deny[info] style rules
func processSingleDenyPolicyResult(
	resultSet rego.ResultSet,
	resource *models.ResourceState,
	metadata Metadata,
	defaultRemediation string,
) ([]models.RuleResult, error) {
	policyResults := []policyResult{}
	if err := unmarshalResultSet(resultSet, &policyResults); err != nil {
		// It might be a fugue deny[msg] style rule in this case. Try that as a
		// fallback.
		return processFugueDenyString(resultSet, resource, metadata)
	}
	results := []models.RuleResult{}
	resourceKey := ResourceKey{
		ID:        resource.Id,
		Type:      resource.ResourceType,
		Namespace: resource.Namespace,
	}
	for _, r := range policyResults {
		result := newRuleResultBuilder()
		result.setPrimaryResource(resourceKey)
		for _, attr := range r.Attributes {
			result.addResourceAttribute(resourceKey, attr)
		}

		result.messages = append(result.messages, r.Message)
		if r.Severity != "" {
			result.severity = r.Severity
		} else {
			result.severity = metadata.Severity
		}
		if r.Remediation != "" {
			result.remediation = r.Remediation
		} else {
			result.remediation = defaultRemediation
		}
		results = append(results, result.toRuleResult())
	}

	if len(results) == 0 {
		// No denies: generate an allow
		result := newRuleResultBuilder()
		result.setPrimaryResource(resourceKey)
		result.passed = true
		result.severity = metadata.Severity
		results = append(results, result.toRuleResult())
	}

	return results, nil
}
