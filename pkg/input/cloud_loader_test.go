package input_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/snyk/policy-engine/pkg/input"
	"github.com/snyk/policy-engine/pkg/input/cloudapi"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/stretchr/testify/assert"
)

type mockClient struct {
	t              *testing.T
	orgID          string
	expectedParams cloudapi.ResourcesParameters
	resources      []cloudapi.ResourceObject
	err            error
}

func (c *mockClient) Resources(_ context.Context, orgID string, params cloudapi.ResourcesParameters) ([]cloudapi.ResourceObject, error) {
	assert.Equal(c.t, c.orgID, orgID)
	assert.Equal(c.t, c.expectedParams, params)
	if c.err != nil {
		return nil, c.err
	}
	return c.resources, nil
}

func TestGetState(t *testing.T) {
	orgID := "organization-id"
	testCases := []struct {
		name            string
		params          cloudapi.ResourcesParameters
		clientResources []cloudapi.ResourceObject
		clientErr       error
		expected        *models.State
		expectedErr     error
	}{
		{
			name: "converts resources and params as expected",
			params: cloudapi.ResourcesParameters{
				ResourceType: []string{
					"aws_s3_bucket",
					"aws_s3_bucket_public_access_block",
				},
				Location: []string{
					"us-east-1",
				},
			},
			clientResources: []cloudapi.ResourceObject{
				{
					ID:   "id_1",
					Type: "aws_s3_bucket",
					Attributes: cloudapi.ResourceAttributes{
						Namespace:    "us-east-1",
						ResourceType: "aws_s3_bucket",
						ResourceID:   "some-bucket",
						Tags: map[string]interface{}{
							"Environment": "test",
							"Invalid":     []string{"this", "will", "get", "dropped"},
						},
						State: map[string]interface{}{
							"bucket": "some-bucket",
						},
					},
				},
				{
					ID:   "id_2",
					Type: "aws_s3_bucket",
					Attributes: cloudapi.ResourceAttributes{
						Namespace:    "us-east-1",
						ResourceType: "aws_s3_bucket",
						ResourceID:   "some-public-bucket",
						Tags: map[string]interface{}{
							"Environment": "dev",
						},
						State: map[string]interface{}{
							"bucket": "some-public-bucket",
						},
					},
				},
				{
					ID:   "id_3",
					Type: "aws_s3_bucket_public_access_block",
					Attributes: cloudapi.ResourceAttributes{
						Namespace:    "us-east-1",
						ResourceType: "aws_s3_bucket_public_access_block",
						ResourceID:   "some-bucket",
						Tags: map[string]interface{}{
							"Environment": "test",
						},
						State: map[string]interface{}{
							"bucket":              "some-bucket",
							"block_public_policy": true,
						},
					},
				},
			},
			expected: &models.State{
				InputType:           input.CloudScan.Name,
				EnvironmentProvider: "cloud",
				Scope: map[string]interface{}{
					"org_id": orgID,
					"resource_type": []string{
						"aws_s3_bucket",
						"aws_s3_bucket_public_access_block",
					},
					"location": []string{
						"us-east-1",
					},
				},
				Resources: map[string]map[string]models.ResourceState{
					"aws_s3_bucket": {
						"some-bucket": models.ResourceState{
							Id:           "some-bucket",
							ResourceType: "aws_s3_bucket",
							Namespace:    "us-east-1",
							Tags: map[string]string{
								"Environment": "test",
							},
							Attributes: map[string]interface{}{
								"bucket": "some-bucket",
							},
						},
						"some-public-bucket": models.ResourceState{
							Id:           "some-public-bucket",
							ResourceType: "aws_s3_bucket",
							Namespace:    "us-east-1",
							Tags: map[string]string{
								"Environment": "dev",
							},
							Attributes: map[string]interface{}{
								"bucket": "some-public-bucket",
							},
						},
					},
					"aws_s3_bucket_public_access_block": {
						"some-bucket": models.ResourceState{
							Id:           "some-bucket",
							ResourceType: "aws_s3_bucket_public_access_block",
							Namespace:    "us-east-1",
							Tags: map[string]string{
								"Environment": "test",
							},
							Attributes: map[string]interface{}{
								"bucket":              "some-bucket",
								"block_public_policy": true,
							},
						},
					},
				},
			},
		},
		{
			name: "handles an empty response",
			params: cloudapi.ResourcesParameters{
				ResourceType: []string{
					"aws_s3_bucket",
					"aws_s3_bucket_public_access_block",
				},
				Location: []string{
					"us-east-1",
				},
			},
			clientResources: []cloudapi.ResourceObject{},
			expected: &models.State{
				InputType:           input.CloudScan.Name,
				EnvironmentProvider: "cloud",
				Scope: map[string]interface{}{
					"org_id": orgID,
					"resource_type": []string{
						"aws_s3_bucket",
						"aws_s3_bucket_public_access_block",
					},
					"location": []string{
						"us-east-1",
					},
				},
				Resources: map[string]map[string]models.ResourceState{},
			},
		},
		{
			name: "wraps client errors",
			params: cloudapi.ResourcesParameters{
				ResourceType: []string{
					"aws_cloudtrail",
				},
				EnvironmentID: []string{
					"some-environment-id",
				},
			},
			clientErr:   fmt.Errorf("some client error"),
			expectedErr: input.ErrFailedToFetchCloudState,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := &mockClient{
				t:              t,
				orgID:          orgID,
				expectedParams: tc.params,
				resources:      tc.clientResources,
				err:            tc.clientErr,
			}
			loader := input.CloudLoader{Client: client}
			resources, err := loader.GetState(context.TODO(), orgID, tc.params)
			assert.Equal(t, tc.expected, resources)
			assert.ErrorIs(t, err, tc.expectedErr)
		})
	}
}
