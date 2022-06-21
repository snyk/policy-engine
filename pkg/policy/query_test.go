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

func TestResolveResources_SingleResolver_ReturnsZeroResourcesWhenNoResolversMatch(t *testing.T) {
	q := &policy.Query{ResourcesResolver: policy.ResourcesResolver(nonMatchingResolver)}
	res, err := q.ResolveResources(context.Background(), policy.ResourcesQuery{})
	require.NoError(t, err)
	assert.Empty(t, res)
}

func TestResolveResources_ComposedWithOr_ReturnsResourcesFromFirstMatchingResolver(t *testing.T) {
	query := policy.ResourcesQuery{ResourceType: "a-resource-type"}
	expectedResources := []models.ResourceState{
		{
			Id: "some-resource",
		},
	}
	spyResolver := func(ctx context.Context, req policy.ResourcesQuery) (policy.ResourcesResult, error) {
		assert.Equal(t, req, query)
		return policy.ResourcesResult{
			ScopeFound: true,
			Resources:  expectedResources,
		}, nil
	}
	q := &policy.Query{
		ResourcesResolver: policy.ResourcesResolver(nonMatchingResolver).
			Or(spyResolver).
			Or(panickyResolver),
	}
	res, err := q.ResolveResources(context.Background(), query)
	require.NoError(t, err)
	assert.Equal(t, expectedResources, res)
}

func TestResolveResources_ComposedWithOr_ReturnsErrorFromFirstResolverThatErrors(t *testing.T) {
	query := policy.ResourcesQuery{ResourceType: "a-resource-type"}
	spyResolver := func(ctx context.Context, req policy.ResourcesQuery) (policy.ResourcesResult, error) {
		assert.Equal(t, req, query)
		return policy.ResourcesResult{}, errors.New("oops")
	}
	q := &policy.Query{
		ResourcesResolver: policy.ResourcesResolver(nonMatchingResolver).
			Or(spyResolver).
			Or(panickyResolver),
	}
	_, err := q.ResolveResources(context.Background(), query)
	require.EqualError(t, err, "error in ResourcesResolver: oops")
}

func TestResolveResources_ComposedWithAnd_ReturnsResourcesFromBothMatchingResolvers(t *testing.T) {
	query := policy.ResourcesQuery{ResourceType: "a-resource-type"}

	expectedResources1 := []models.ResourceState{
		{
			Id: "some-resource-1",
		},
	}
	spyResolver1 := func(ctx context.Context, req policy.ResourcesQuery) (policy.ResourcesResult, error) {
		assert.Equal(t, req, query)
		return policy.ResourcesResult{
			ScopeFound: true,
			Resources:  expectedResources1,
		}, nil
	}
	expectedResources2 := []models.ResourceState{
		{
			Id: "some-resource-2",
		},
	}
	spyResolver2 := func(ctx context.Context, req policy.ResourcesQuery) (policy.ResourcesResult, error) {
		assert.Equal(t, req, query)
		return policy.ResourcesResult{
			ScopeFound: true,
			Resources:  expectedResources2,
		}, nil
	}

	q := &policy.Query{
		ResourcesResolver: policy.ResourcesResolver(spyResolver1).
			And(spyResolver2),
	}
	res, err := q.ResolveResources(context.Background(), query)
	require.NoError(t, err)
	assert.Equal(t, append(expectedResources1, expectedResources2...), res)
}

func TestResolveResources_ComposedWithAnd_ReturnsErrorFromFirstResolverThatErrors(t *testing.T) {
	query := policy.ResourcesQuery{ResourceType: "a-resource-type"}
	spyResolver := func(ctx context.Context, req policy.ResourcesQuery) (policy.ResourcesResult, error) {
		assert.Equal(t, req, query)
		return policy.ResourcesResult{}, errors.New("oops")
	}
	q := &policy.Query{
		ResourcesResolver: policy.ResourcesResolver(nonMatchingResolver).
			And(spyResolver).
			And(panickyResolver),
	}
	_, err := q.ResolveResources(context.Background(), query)
	require.EqualError(t, err, "error in ResourcesResolver: oops")
}

func TestResolveResources_ComplexChainOfAndsAndOrs(t *testing.T) {
	query := policy.ResourcesQuery{ResourceType: "a-resource-type"}

	expectedResources := []models.ResourceState{
		{Id: "some-resource-1"},
		{Id: "some-resource-2"},
		{Id: "some-resource-3"},
	}

	mkstub := func(id string) policy.ResourcesResolver {
		return func(ctx context.Context, req policy.ResourcesQuery) (policy.ResourcesResult, error) {
			return policy.ResourcesResult{
				ScopeFound: true,
				Resources: []models.ResourceState{
					{Id: id},
				},
			}, nil
		}
	}

	q := &policy.Query{
		ResourcesResolver: policy.ResourcesResolver(nonMatchingResolver).
			Or(
				mkstub("some-resource-1").And(
					policy.ResourcesResolver(nonMatchingResolver).Or(mkstub("some-resource-2")).And(
						mkstub("some-resource-3").And(nonMatchingResolver).Or(panickyResolver),
					),
				),
			).
			Or(panickyResolver),
	}
	res, err := q.ResolveResources(context.Background(), query)
	require.NoError(t, err)
	assert.Equal(t, expectedResources, res)
}

func nonMatchingResolver(ctx context.Context, req policy.ResourcesQuery) (policy.ResourcesResult, error) {
	return policy.ResourcesResult{ScopeFound: false}, nil
}

func panickyResolver(ctx context.Context, req policy.ResourcesQuery) (policy.ResourcesResult, error) {
	panic("this resolver should not have been reached!")
}
