package legacyiac_test

import (
	"testing"

	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/policy/legacyiac"
	"github.com/stretchr/testify/assert"
)

func TestRawTfInput(t *testing.T) {
	for _, tc := range []struct {
		name     string
		state    *models.State
		expected map[string]map[string]map[string]interface{}
	}{
		{
			name: "resources",
			state: &models.State{
				Resources: map[string]map[string]models.ResourceState{
					"aws_s3_bucket": {
						"bucket_1": {
							Attributes: map[string]interface{}{
								"property": map[string]interface{}{
									"sub_property": []string{"foo"},
								},
							},
						},
					},
					"aws_iam_policy": {
						"policy_1": {
							Attributes: map[string]interface{}{
								"other_property": map[string]interface{}{
									"other_sub_property": []string{"bar"},
								},
							},
						},
					},
				},
			},
			expected: map[string]map[string]map[string]interface{}{
				"data": {},
				"resource": {
					"aws_s3_bucket": {
						"bucket_1": map[string]interface{}{
							"property": map[string]interface{}{
								"sub_property": []string{"foo"},
							},
						},
					},
					"aws_iam_policy": {
						"policy_1": map[string]interface{}{
							"other_property": map[string]interface{}{
								"other_sub_property": []string{"bar"},
							},
						},
					},
				},
			},
		},
		{
			name: "data",
			state: &models.State{
				Resources: map[string]map[string]models.ResourceState{
					"data.aws_s3_bucket": {
						"bucket_1": {
							Attributes: map[string]interface{}{
								"property": map[string]interface{}{
									"sub_property": []string{"foo"},
								},
							},
						},
					},
					"data.aws_iam_policy": {
						"policy_1": {
							Attributes: map[string]interface{}{
								"other_property": map[string]interface{}{
									"other_sub_property": []string{"bar"},
								},
							},
						},
					},
				},
			},
			expected: map[string]map[string]map[string]interface{}{
				"resource": {},
				"data": {
					"aws_s3_bucket": {
						"bucket_1": map[string]interface{}{
							"property": map[string]interface{}{
								"sub_property": []string{"foo"},
							},
						},
					},
					"aws_iam_policy": {
						"policy_1": map[string]interface{}{
							"other_property": map[string]interface{}{
								"other_sub_property": []string{"bar"},
							},
						},
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := legacyiac.NewTfInput(tc.state).Raw()
			assert.Equal(t, tc.expected, output)
		})
	}
}

func TestTfParseMsg(t *testing.T) {
	tfInput := legacyiac.NewTfInput(&models.State{
		Resources: map[string]map[string]models.ResourceState{
			"aws_s3_bucket": {
				"bucket": {
					Attributes: map[string]interface{}{},
				},
			},
			"data.aws_s3_bucket": {
				"data_bucket": {
					Attributes: map[string]interface{}{},
				},
			},
		},
	})
	for _, tc := range []struct {
		msg      string
		expected legacyiac.ParsedMsg
	}{
		{
			msg: "input.resource.aws_s3_bucket[bucket_1].property.sub_property[0]",
			expected: legacyiac.ParsedMsg{
				ResourceID:   "aws_s3_bucket.bucket_1",
				ResourceType: "aws_s3_bucket",
				Path:         []interface{}{"property", "sub_property", 0},
			},
		},
		{
			msg: "resource.aws_s3_bucket[bucket_1].property.sub_property[0]",
			expected: legacyiac.ParsedMsg{
				ResourceID:   "aws_s3_bucket.bucket_1",
				ResourceType: "aws_s3_bucket",
				Path:         []interface{}{"property", "sub_property", 0},
			},
		},
		{
			msg: "resource.aws_s3_bucket[bucket_1]",
			expected: legacyiac.ParsedMsg{
				ResourceID:   "aws_s3_bucket.bucket_1",
				ResourceType: "aws_s3_bucket",
				Path:         nil,
			},
		},
		{
			msg: "aws_s3_bucket[bucket_1].property.sub_property[0]",
			expected: legacyiac.ParsedMsg{
				ResourceID:   "aws_s3_bucket.bucket_1",
				ResourceType: "aws_s3_bucket",
				Path:         []interface{}{"property", "sub_property", 0},
			},
		},
		{
			msg: "aws_s3_bucket.bucket_1.property.sub_property[0]",
			expected: legacyiac.ParsedMsg{
				ResourceID:   "aws_s3_bucket.bucket_1",
				ResourceType: "aws_s3_bucket",
				Path:         []interface{}{"property", "sub_property", 0},
			},
		},
		{
			msg: "aws_s3_bucket[data_bucket].property.sub_property[0]",
			expected: legacyiac.ParsedMsg{
				ResourceID:   "data.aws_s3_bucket.data_bucket",
				ResourceType: "data.aws_s3_bucket",
				Path:         []interface{}{"property", "sub_property", 0},
			},
		},
	} {
		t.Run(tc.msg, func(t *testing.T) {
			output := tfInput.ParseMsg(tc.msg)
			assert.Equal(t, tc.expected, output)
		})
	}
}
