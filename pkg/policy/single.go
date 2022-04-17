package policy

import (
	"context"

	"github.com/open-policy-agent/opa/rego"
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
	metadata, err := p.Metadata(ctx, options.RegoOptions)
	if err != nil {
		return nil, err
	}
	opts := append(
		options.RegoOptions,
		rego.Query(p.judgementRule.query()),
	)
	query, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}
	ruleResults := []models.RuleResult{}
	rt := p.resourceType()
	var missingResourceTypes []string
	if resources, ok := options.Input.Resources[rt]; ok {
		for _, resource := range resources {
			resultSet, err := query.Eval(ctx, rego.EvalInput(resource.Attributes))
			if err != nil {
				return nil, err
			}
			ruleResult, err := p.processResultSet(resultSet, &resource, metadata)
			if err != nil {
				return nil, err
			}
			ruleResults = append(ruleResults, ruleResult...)
		}
	} else {
		missingResourceTypes = append(missingResourceTypes, rt)
	}
	return &models.RuleResults{
		Id:                   metadata.ID,
		Title:                metadata.Title,
		Description:          metadata.Description,
		Controls:             metadata.Controls,
		Results:              ruleResults,
		MissingResourceTypes: missingResourceTypes,
	}, nil
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
