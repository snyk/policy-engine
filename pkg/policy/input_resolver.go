package policy

import (
	"context"

	"github.com/snyk/policy-engine/pkg/models"
)

type inputResolver struct {
	calledWith map[string]bool
	input      *models.State
}

func newInputResolver(input *models.State) *inputResolver {
	return &inputResolver{
		calledWith: map[string]bool{},
		input:      input,
	}
}

func (r *inputResolver) resolver() ResourcesResolver {
	return ResourcesResolver{
		Resolve: func(ctx context.Context, query ResourcesQuery) (ResourcesResult, error) {
			if !ScopeMatches(query.Scope, r.input.Scope) {
				return ResourcesResult{ScopeFound: false}, nil
			}
			ret := ResourcesResult{ScopeFound: true}
			if resources, ok := r.input.Resources[query.ResourceType]; ok {
				ret.ScopeFound = true
				for _, resource := range resources {
					ret.Resources = append(ret.Resources, resource)
				}
			}
			r.calledWith[query.ResourceType] = true
			return ret, nil
		},
	}
}
