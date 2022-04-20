package policy

import (
	"context"

	"github.com/open-policy-agent/opa/rego"
	"github.com/snyk/unified-policy-engine/pkg/models"
)

// ProcessSingleResultSet functions extract RuleResult models from the ResultSet of
// multi-resource type rules.
type ProcessMultiResultSet func(
	resultSet rego.ResultSet,
	metadata Metadata,
	resources map[string]map[string]models.RuleResultResource,
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
) (*models.RuleResults, error) {
	metadata, err := p.Metadata(ctx, options.RegoOptions)
	if err != nil {
		return nil, err
	}
	// buff := topdown.NewBufferTracer()
	opts := append(
		options.RegoOptions,
		rego.Query(p.judgementRule.query()),
		rego.Input(options.Input),
	)
	builtins := NewBuiltins(options.Input)
	opts = append(opts, builtins.Rego()...)
	query, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}
	// resultSet, err := query.Eval(ctx, rego.EvalQueryTracer(buff))
	resultSet, err := query.Eval(ctx)
	if err != nil {
		return nil, err
	}
	resources, err := p.resources(ctx, opts)
	if err != nil {
		return nil, err
	}
	// for _, event := range *buff {
	// 	fmt.Printf("%d\t%s: %s\n", event.QueryID, event.Op, string(event.Location.Text))
	// }
	ruleResults, err := p.processResultSet(resultSet, metadata, resources)
	if err != nil {
		return nil, err
	}
	return &models.RuleResults{
		Id:            metadata.ID,
		Title:         metadata.Title,
		Description:   metadata.Description,
		Controls:      metadata.Controls,
		Results:       ruleResults,
		ResourceTypes: builtins.ResourceTypes(),
	}, nil
}

// This is a ProcessMultiResultSet func for the new deny[info] style rules
func processMultiDenyPolicyResult(
	resultSet rego.ResultSet,
	metadata Metadata,
	resources map[string]map[string]models.RuleResultResource,
) ([]models.RuleResult, error) {
	policyResults := []policyResult{}
	if err := unmarshalResultSet(resultSet, &policyResults); err != nil {
		return nil, err
	}
	results := []models.RuleResult{}
	deniedResourceIDs := map[string]bool{}
	for _, result := range policyResults {
		ruleResult := models.RuleResult{
			Passed:       false,
			Message:      result.Message,
			Severity:     metadata.Severity,
			ResourceType: result.ResourceType,
		}
		if result.Resource != nil {
			ruleResult.ResourceId = result.Resource.ID
			if ruleResultResources, ok := resources[ruleResult.ResourceId]; ok {
				ruleResult.Resources = ruleResultResources
			} else if len(result.Attribute) > 0 {
				ruleResult.Resources = map[string]models.RuleResultResource{
					result.Resource.ID: {
						Attributes: []models.RuleResultResourceAttribute{
							{
								Path: result.Attribute,
							},
						},
					},
				}
			}
			deniedResourceIDs[result.Resource.ID] = true
		}
		results = append(results, ruleResult)
	}
	for resourceID, relatedResources := range resources {
		if deniedResourceIDs[resourceID] {
			continue
		}
		results = append(results, models.RuleResult{
			Passed:     true,
			ResourceId: resourceID,
			Severity:   metadata.Severity,
			Resources:  relatedResources,
		})
	}
	return results, nil
}
