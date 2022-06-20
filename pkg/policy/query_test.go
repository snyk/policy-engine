package policy_test

import (
	"context"
	"errors"
	"testing"

	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveResources_ReturnsZeroResourcesWhenNoResolversMatch(t *testing.T) {
	q := &policy.Query{ResourcesResolver: nonMatchingResolver()}
	res, err := q.ResolveResources(context.Background(), policy.ResourcesQuery{})
	require.NoError(t, err)
	assert.Empty(t, res)
}

func TestResolveResources_ReturnsResourcesFromFirstMatchingResolver(t *testing.T) {
	query := policy.ResourcesQuery{ResourceType: "a-resource-type"}
	expectedResources := []models.ResourceState{
		{
			Id: "some-resource",
		},
	}
	spyResolver := policy.ResourcesResolver{
		Resolve: func(ctx context.Context, req policy.ResourcesQuery) (policy.ResourcesResult, error) {
			assert.Equal(t, req, query)
			return policy.ResourcesResult{
				ScopeFound: true,
				Resources:  expectedResources,
			}, nil
		},
	}
	q := &policy.Query{
		ResourcesResolver: nonMatchingResolver().Or(spyResolver.Or(panickyResolver())),
	}
	res, err := q.ResolveResources(context.Background(), query)
	require.NoError(t, err)
	assert.Equal(t, expectedResources, res)
}

func TestResolveResources_ReturnsErrorFromFirstResolverThatErrors(t *testing.T) {
	query := policy.ResourcesQuery{ResourceType: "a-resource-type"}
	spyResolver := policy.ResourcesResolver{
		Resolve: func(ctx context.Context, req policy.ResourcesQuery) (policy.ResourcesResult, error) {
			assert.Equal(t, req, query)
			return policy.ResourcesResult{}, errors.New("oops")
		},
	}
	q := &policy.Query{
		ResourcesResolver: nonMatchingResolver().Or(spyResolver.Or(panickyResolver())),
	}
	_, err := q.ResolveResources(context.Background(), query)
	require.EqualError(t, err, "error in ResourcesResolver: oops")
}

func nonMatchingResolver() policy.ResourcesResolver {
	return policy.ResourcesResolver{
		Resolve: func(ctx context.Context, req policy.ResourcesQuery) (policy.ResourcesResult, error) {
			return policy.ResourcesResult{ScopeFound: false}, nil
		},
	}
}

func panickyResolver() policy.ResourcesResolver {
	return policy.ResourcesResolver{
		Resolve: func(ctx context.Context, req policy.ResourcesQuery) (policy.ResourcesResult, error) {
			panic("this resolver should not have been reached!")
		},
	}
}
