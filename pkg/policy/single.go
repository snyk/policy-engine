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

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/topdown"

	"github.com/snyk/policy-engine/pkg/logging"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/policy/inferattributes"
	"github.com/snyk/policy-engine/pkg/rego"
)

// SingleResourcePolicy represents a policy that takes a single resource as input.
type SingleResourcePolicy struct {
	*BasePolicy
	Query            string
	processorFactory func(
		resource *models.ResourceState,
		metadata *Metadata,
		defaultRemediation string,
	) SingleResourceProcessor
}

// SingleResourceProcessor can turn rego results into the results model we want.
type SingleResourceProcessor interface {
	Process(ast.Value) error
	ProcessResource(ast.Value) error
	Results() []models.RuleResult
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
			processor := p.processorFactory(
				&resource,
				&metadata,
				defaultRemediation,
			)
			err = options.RegoState.Query(
				ctx,
				rego.Query{
					Tracers: []topdown.QueryTracer{tracer},
					Query:   p.Query,
					Input:   inputDoc.Value,
					Timeout: options.Timeout,
				},
				func(val ast.Value) error {
					return processor.Process(val)
				},
			)
			if err != nil {
				logger.WithError(err).Error(ctx, "failed to evaluate rule for resource")
				err = fmt.Errorf("%w '%s': %v", FailedToEvaluateResource, resource.Id, err)
				output.Errors = append(output.Errors, err.Error())
				return []models.RuleResults{output}, err
			}

			// The single-resource type policies may define a resources rule to provide additional
			// context for the resource.
			if p.resourcesRule.queryElem() != "" {
				err = options.RegoState.Query(
					ctx,
					rego.Query{
						Query:   p.resourcesRule.queryElem(),
						Input:   inputDoc.Value,
						Timeout: options.Timeout,
					},
					processor.ProcessResource,
				)
				if err != nil {
					logger.WithError(err).Error(ctx, "Failed to query resources")
					err = fmt.Errorf("%w: %v", FailedToQueryResources, err)
					output.Errors = append(output.Errors, err.Error())
					return []models.RuleResults{output}, err
				}
			}

			results = processor.Results()

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

type singleDenyProcessor struct {
	resource           *models.ResourceState
	metadata           *Metadata
	defaultRemediation string
	builder            *ruleResultBuilder
}

func NewSingleDenyProcessor(
	resource *models.ResourceState,
	metadata *Metadata,
	defaultRemediation string,
) SingleResourceProcessor {
	return &singleDenyProcessor{
		resource:           resource,
		metadata:           metadata,
		defaultRemediation: defaultRemediation,
	}
}

func (b *singleDenyProcessor) resourceKey() ResourceKey {
	return ResourceKey{
		ID:        b.resource.Id,
		Type:      b.resource.ResourceType,
		Namespace: b.resource.Namespace,
	}
}

func (b *singleDenyProcessor) Process(val ast.Value) error {
	policyResult := policyResult{}
	if err := rego.Bind(val, &policyResult); err != nil {
		// It might be a fugue deny[msg] style rule in this case. Try that as a
		// fallback.
		var denyString string
		if strErr := rego.Bind(val, &denyString); strErr != nil {
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
	result.addGraph(policyResult.Graph)
	b.builder = result
	return nil
}

func (b *singleDenyProcessor) ProcessResource(val ast.Value) error {
	var result resourcesResult
	if err := rego.Bind(val, &result); err != nil {
		return err
	}
	b.generateAllowIfNoDeny()
	b.builder.addContext(result.Context)
	return nil
}

func (b *singleDenyProcessor) Results() []models.RuleResult {
	b.generateAllowIfNoDeny()
	return []models.RuleResult{b.builder.toRuleResult()}
}

func (b *singleDenyProcessor) generateAllowIfNoDeny() {
	// If we haven't seen a deny (Process was not called), generate an allow result.
	if b.builder == nil {
		b.builder = newRuleResultBuilder()
		b.builder.setPrimaryResource(b.resourceKey())
		b.builder.passed = true
		b.builder.severity = b.metadata.Severity
	}
}
