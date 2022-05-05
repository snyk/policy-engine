package policy

import (
	"context"

	"github.com/open-policy-agent/opa/rego"
	"github.com/snyk/unified-policy-engine/pkg/logging"
	"github.com/snyk/unified-policy-engine/pkg/models"
)

// ProcessSingleResultSet functions extract RuleResult models from the ResultSet of
// multi-resource type rules.
type ProcessMultiResultSet func(
	resultSet rego.ResultSet,
	metadata Metadata,
	resources map[string]*resourceResults,
) ([]models.RuleResult, error)

// MultiResourcePolicy represents a policy that takes multiple resources as input.
type MultiResourcePolicy struct {
	*BasePolicy
	processResultSet ProcessMultiResultSet
}

// Eval will evaluate the policy on the given input.
func (p *MultiResourcePolicy) Eval(
	ctx context.Context,
	options EvalOptions,
) ([]models.RuleResults, error) {
	logger := options.Logger
	if logger == nil {
		logger = logging.DefaultLogger
	}
	logger = logger.WithField(logging.PACKAGE, p.Package()).
		WithField(logging.POLICY_TYPE, "multi_resource").
		WithField(logging.JUDGEMENT_NAME, p.judgementRule.name).
		WithField(logging.JUDGEMENT_KEY, p.judgementRule.key)
	output := models.RuleResults{}
	metadata, err := p.Metadata(ctx, options.RegoOptions)
	if err != nil {
		logger.Error(ctx, "Failed to obtain metadata")
		output.Errors = append(output.Errors, err.Error())
		return []models.RuleResults{output}, err
	}
	output.Id = metadata.ID
	output.Title = metadata.Title
	output.Description = metadata.Description
	output.Controls = metadata.Controls
	opts := append(
		options.RegoOptions,
		rego.Query(p.judgementRule.query()),
		rego.Input(options.Input),
	)
	builtins := NewBuiltins(options.Input)
	opts = append(opts, builtins.Rego()...)
	query, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		logger.Error(ctx, "Failed to prepare for eval")
		output.Errors = append(output.Errors, err.Error())
		return []models.RuleResults{output}, err
	}
	resultSet, err := query.Eval(ctx)
	if err != nil {
		logger.Error(ctx, "Failed to evaluate query")
		output.Errors = append(output.Errors, err.Error())
		return []models.RuleResults{output}, err
	}
	resources, err := p.resources(ctx, opts)
	if err != nil {
		logger.Error(ctx, "Failed to query resources")
		output.Errors = append(output.Errors, err.Error())
		return []models.RuleResults{output}, err
	}
	ruleResults, err := p.processResultSet(resultSet, metadata, resources)
	if err != nil {
		logger.Error(ctx, "Failed to process result set")
		output.Errors = append(output.Errors, err.Error())
		return []models.RuleResults{output}, err
	}
	output.ResourceTypes = builtins.ResourceTypes()
	output.Results = ruleResults
	return []models.RuleResults{output}, nil
}

// This is a ProcessMultiResultSet func for the new deny[info] style rules
func processMultiDenyPolicyResult(
	resultSet rego.ResultSet,
	metadata Metadata,
	resources map[string]*resourceResults,
) ([]models.RuleResult, error) {
	policyResults := []policyResult{}
	if err := unmarshalResultSet(resultSet, &policyResults); err != nil {
		return nil, err
	}
	results := []models.RuleResult{}
	deniedCorrelations := map[string]bool{}
	for _, result := range policyResults {
		ruleResult := models.RuleResult{
			Passed:       false,
			Message:      result.Message,
			Severity:     metadata.Severity,
			ResourceType: result.ResourceType,
		}
		if result.Resource != nil {
			ruleResult.ResourceId = result.Resource.ID
			ruleResult.ResourceNamespace = result.Resource.Namespace
			ruleResult.ResourceType = result.Resource.ResourceType

			resource := models.RuleResultResource{
				Id:        result.Resource.ID,
				Type:      result.Resource.ResourceType,
				Namespace: result.Resource.Namespace,
			}
			for _, attr := range result.Attributes {
				resource.Attributes = append(resource.Attributes, models.RuleResultResourceAttribute{
					Path: attr,
				})
			}

			var rr *resourceResults
			rr, ok := resources[result.GetCorrelation()]
			if !ok {
				rr = newResourceResults()
			}
			rr.addRuleResultResource(resource)

			ruleResult.Resources = rr.resources()
			deniedCorrelations[result.GetCorrelation()] = true
		}
		results = append(results, ruleResult)
	}
	for correlation, relatedResources := range resources {
		if deniedCorrelations[correlation] {
			continue
		}
		ruleResultResources := relatedResources.resources()
		ruleResult := models.RuleResult{
			Passed:    true,
			Severity:  metadata.Severity,
			Resources: ruleResultResources,
		}
		for _, resource := range ruleResultResources {
			if RuleResultResourceKey(resource).Correlation() == correlation {
				ruleResult.ResourceId = resource.Id
				ruleResult.ResourceNamespace = resource.Namespace
				ruleResult.ResourceType = resource.Type
			}
		}

		results = append(results, ruleResult)
	}
	return results, nil
}
