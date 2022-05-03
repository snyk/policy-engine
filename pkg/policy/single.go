package policy

import (
	"context"

	"github.com/open-policy-agent/opa/rego"
	"github.com/snyk/unified-policy-engine/pkg/logging"
	"github.com/snyk/unified-policy-engine/pkg/models"
)

// ProcessSingleResultSet functions extract RuleResult models from the ResultSet of
// single-resource type rules.
type ProcessSingleResultSet func(
	resultSet rego.ResultSet,
	resource *models.ResourceState,
	metadata Metadata,
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
) (*models.RuleResults, error) {
	logger := options.Logger
	if logger == nil {
		logger = logging.DefaultLogger
	}
	logger = logger.WithField(logging.PACKAGE, p.Package()).
		WithField(logging.POLICY_TYPE, "single_resource").
		WithField(logging.JUDGEMENT_NAME, p.judgementRule.name).
		WithField(logging.JUDGEMENT_KEY, p.judgementRule.key).
		WithField(logging.RESOURCE_TYPE, p.resourceType()).
		WithField(logging.INPUT_TYPE, p.InputType())
	output := &models.RuleResults{}
	metadata, err := p.Metadata(ctx, options.RegoOptions)
	if err != nil {
		logger.Error(ctx, "Failed to obtain metadata")
		output.Errors = append(output.Errors, err.Error())
		return output, err
	}
	output.Id = metadata.ID
	output.Title = metadata.Title
	output.Description = metadata.Description
	output.Controls = metadata.Controls
	opts := append(
		options.RegoOptions,
		rego.Query(p.judgementRule.query()),
	)
	query, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		logger.Error(ctx, "Failed to prepare for eval")
		output.Errors = append(output.Errors, err.Error())
		return output, err
	}
	ruleResults := []models.RuleResult{}
	rt := p.resourceType()
	output.ResourceTypes = []string{rt}
	if resources, ok := options.Input.Resources[rt]; ok {
		for _, resource := range resources {
			logger := logger.WithField(logging.RESOURCE_ID, resource.Id)
			resultSet, err := query.Eval(ctx, rego.EvalInput(resource.Attributes))
			if err != nil {
				logger.Error(ctx, "Failed to evaluate resource")
				output.Errors = append(output.Errors, err.Error())
				return output, err
			}
			ruleResult, err := p.processResultSet(resultSet, &resource, metadata)
			if err != nil {
				logger.Error(ctx, "Failed to process result set")
				output.Errors = append(output.Errors, err.Error())
				return output, err
			}
			ruleResults = append(ruleResults, ruleResult...)
		}
	}
	output.Results = ruleResults
	return output, nil
}

// This is a ProcessSingleResultSet func for the new deny[info] style rules
func processSingleDenyPolicyResult(
	resultSet rego.ResultSet,
	resource *models.ResourceState,
	metadata Metadata,
) ([]models.RuleResult, error) {
	policyResults := []policyResult{}
	if err := unmarshalResultSet(resultSet, &policyResults); err != nil {
		// It might be a fugue deny[msg] style rule in this case. Try that as a
		// fallback.
		return processFugueDenyString(resultSet, resource, metadata)
	}
	results := []models.RuleResult{}
	for _, r := range policyResults {
		result := models.RuleResult{
			Message:    r.Message,
			ResourceId: resource.Id,
			Severity:   metadata.Severity,
		}
		if len(r.Attribute) > 0 {
			result.Resources = map[string]models.RuleResultResource{
				resource.Id: {
					Attributes: []models.RuleResultResourceAttribute{
						{
							Path: r.Attribute,
						},
					},
				},
			}
		}
		results = append(results, result)
	}
	return results, nil
}
