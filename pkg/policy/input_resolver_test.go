package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/snyk/policy-engine/pkg/models"
)

func TestInputResolverDeterministic(t *testing.T) {
	resource1 := models.ResourceState{
		Id:           "bucket_1",
		ResourceType: "aws_s3_bucket",
	}
	resource2 := models.ResourceState{
		Id:           "bucket_2",
		ResourceType: "aws_s3_bucket",
	}
	input := models.State{
		Resources: map[string]map[string]models.ResourceState{
			"aws_s3_bucket": map[string]models.ResourceState{
				resource1.Id: resource1,
				resource2.Id: resource2,
			},
		},
	}
	resolver := NewInputResolver(&input)
	result, err := resolver(context.Background(), ResourcesQuery{
		ResourceType: "aws_s3_bucket",
	})
	require.NoError(t, err)
	require.Equal(t, []models.ResourceState{resource1, resource2}, result.Resources)
}
