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
	"github.com/open-policy-agent/opa/topdown"

	"github.com/snyk/policy-engine/pkg/logging"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/policy/inferattributes"
	"github.com/snyk/policy-engine/pkg/regobind"
)

// ProcessSingleResultSet functions extract RuleResult models from the ResultSet of
// multi-resource type rules.
type ProcessMultiResultSet func(
	metadata Metadata,
	defaultRemediation string,
	resources map[string]*ruleResultBuilder,
) ([]models.RuleResult, error)

// MultiResourcePolicy represents a policy that takes multiple resources as input.
type MultiResourcePolicy struct {
	*BasePolicy
	processorFactory func(metadata Metadata, defaultRemediation string) MultiResourceProcessor
}

// SingleResourceProcessor can turn rego results into the results model we want.
type MultiResourceProcessor interface {
	ProcessValue(ast.Value) error
	ProcessResource(ast.Value) error
	Results() []models.RuleResult
}

// Eval will evaluate the policy on the given input.
func (p *MultiResourcePolicy) Eval(
	ctx context.Context,
	options EvalOptions,
) ([]models.RuleResults, error) {
	logger := options.Logger
	if logger == nil {
		logger = logging.NopLogger
	}
	logger = logger.WithField(logging.PACKAGE, p.Package()).
		WithField(logging.POLICY_TYPE, "multi_resource").
		WithField(logging.JUDGEMENT_NAME, p.judgementRule.name).
		WithField(logging.JUDGEMENT_KEY, p.judgementRule.key)
	output := models.RuleResults{}
	output.Package_ = p.pkg
	metadata, err := p.Metadata(ctx, options.RegoState)
	if err != nil {
		logger.Error(ctx, "Failed to query metadata")
		err = fmt.Errorf("%w: %v", FailedToQueryMetadata, err)
		output.Errors = append(output.Errors, err.Error())
		return []models.RuleResults{output}, err
	}
	defaultRemediation := metadata.RemediationFor(options.Input.InputType)
	metadata.copyToRuleResults(options.Input.InputType, &output)
	builtins := NewBuiltins(options.Input, options.ResourcesResolver)
	tracer := inferattributes.NewTracer()

	query := regobind.Query{
		Query:    p.judgementRule.query(),
		Builtins: builtins.Implementations(),
		Tracers:  []topdown.QueryTracer{tracer},
		Input: ast.NewObject(
			[2]*ast.Term{ast.StringTerm("resources"), ast.ObjectTerm()},
		),
	}
	processor := p.processorFactory(metadata, defaultRemediation)
	err = options.RegoState.Query(
		ctx,
		query,
		processor.ProcessValue,
	)
	if err != nil {
		logger.Error(ctx, "Failed to evaluate rule")
		err = fmt.Errorf("%w: %v", FailedToEvaluateRule, err)
		output.Errors = append(output.Errors, err.Error())
		return []models.RuleResults{output}, err
	}
	err = options.RegoState.Query(
		ctx,
		query.Add(regobind.Query{Query: p.resourcesRule.query()}),
		processor.ProcessResource,
	)
	if err != nil {
		logger.Error(ctx, "Failed to query resources")
		err = fmt.Errorf("%w: %v", FailedToQueryResources, err)
		output.Errors = append(output.Errors, err.Error())
		return []models.RuleResults{output}, err
	}

	ruleResults := processor.Results()
	tracer.InferAttributes(ruleResults)
	output.ResourceTypes = builtins.ResourceTypes()
	output.Results = ruleResults
	return []models.RuleResults{output}, nil
}

type multiDenyProcessor struct {
	metadata           Metadata
	defaultRemediation string

	builders map[string]*ruleResultBuilder
}

func NewMultiDenyProcessor(metadata Metadata, defaultRemediation string) MultiResourceProcessor {
	return &multiDenyProcessor{
		metadata:           metadata,
		defaultRemediation: defaultRemediation,
		builders:           map[string]*ruleResultBuilder{},
	}
}

func (p *multiDenyProcessor) ProcessValue(val ast.Value) error {
	var result policyResult
	if err := regobind.Bind(val, &result); err != nil {
		return err
	}

	correlation := result.GetCorrelation()
	var builder *ruleResultBuilder
	if b, ok := p.builders[correlation]; ok {
		builder = b
	} else {
		builder = newRuleResultBuilder()
		p.builders[correlation] = builder
		builder.severity = p.metadata.Severity
		builder.remediation = p.defaultRemediation
	}

	builder.passed = false
	builder.messages = append(builder.messages, result.Message)
	if result.ResourceType != "" {
		builder.resourceType = result.ResourceType
	}

	if result.PrimaryResource != nil {
		builder.setPrimaryResource(result.PrimaryResource.Key())
	}

	if resource := result.GetResource(); resource != nil {
		resourceKey := resource.Key()
		builder.addResource(resourceKey)
		for _, attr := range result.Attributes {
			builder.addResourceAttribute(resourceKey, attr)
		}
	}
	if result.Remediation != "" {
		builder.remediation = result.Remediation
	}
	if result.Severity != "" {
		builder.severity = result.Severity
	}
	return nil
}

func (p *multiDenyProcessor) ProcessResource(val ast.Value) error {
	var result resourcesResult
	if err := regobind.Bind(val, &result); err != nil {
		return err
	}
	correlation := result.GetCorrelation()
	if _, ok := p.builders[correlation]; !ok {
		p.builders[correlation] = newRuleResultBuilder()
		p.builders[correlation].passed = true
		p.builders[correlation].severity = p.metadata.Severity
		p.builders[correlation].remediation = p.defaultRemediation
	}
	if result.ResourceType != "" {
		p.builders[correlation].setMissingResourceType(result.ResourceType)
	}
	if result.Resource != nil {
		p.builders[correlation].addResource(result.Resource.Key())
	}
	if result.PrimaryResource != nil {
		p.builders[correlation].setPrimaryResource(result.PrimaryResource.Key())
	}
	for _, attr := range result.Attributes {
		p.builders[correlation].addResourceAttribute(result.GetResource().Key(), attr)
	}
	return nil
}

func (p *multiDenyProcessor) Results() []models.RuleResult {
	// Ensure deterministic ordering of results.
	results := make([]models.RuleResult, len(p.builders))
	correlations := []string{}
	for correlation := range p.builders {
		correlations = append(correlations, correlation)
	}
	sort.Strings(correlations)
	for i, correlation := range correlations {
		results[i] = p.builders[correlation].toRuleResult()
	}
	return results
}
