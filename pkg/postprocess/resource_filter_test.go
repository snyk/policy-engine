// © 2022-2023 Snyk Limited All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package postprocess

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/policy-engine/pkg/models"
)

func TestResourceFilter(t *testing.T) {
	namespace := "golden_test/tfplan/resource-changes/plan.json"
	in := models.Results{Results: []models.Result{{
		Input: models.State{
			Resources: map[string]map[string]models.ResourceState{
				"aws_s3_bucket": {
					"aws_s3_bucket.create_bucket": {
						Id:           "aws_s3_bucket.create_bucket",
						ResourceType: "aws_s3_bucket",
						Namespace:    namespace,
						Meta: map[string]interface{}{
							"region": "us-east-1",
							"tfplan": map[string]interface{}{
								"resource_actions": []interface{}{"create"},
							},
						},
						Attributes: map[string]interface{}{
							"acl": "public",
						},
					},
					"aws_s3_bucket.update_bucket": {
						Id:           "aws_s3_bucket.update_bucket",
						ResourceType: "aws_s3_bucket",
						Namespace:    namespace,
						Meta: map[string]interface{}{
							"region": "us-east-1",
							"tfplan": map[string]interface{}{
								"resource_actions": []interface{}{"update"},
							},
						},
						Attributes: map[string]interface{}{
							"acl": "public",
						},
					},
					"aws_s3_bucket.noop_bucket": {
						Id:           "aws_s3_bucket.noop_bucket",
						ResourceType: "aws_s3_bucket",
						Namespace:    namespace,
						Meta: map[string]interface{}{
							"region": "us-east-1",
							"tfplan": map[string]interface{}{
								"resource_actions": []interface{}{"no-op"},
							},
						},
						Attributes: map[string]interface{}{
							"acl": "public",
						},
					},
				},
			},
		},
		RuleResults: []models.RuleResults{
			{
				Id: "SNYK-ABC-01",
				Results: []models.RuleResult{
					{
						Passed:            false,
						ResourceId:        "aws_s3_bucket.create_bucket",
						ResourceType:      "aws_s3_bucket",
						ResourceNamespace: namespace,
					},
					{
						Passed:            false,
						ResourceId:        "aws_s3_bucket.update_bucket",
						ResourceType:      "aws_s3_bucket",
						ResourceNamespace: namespace,
					},
					{
						Passed:            false,
						ResourceId:        "aws_s3_bucket.noop_bucket",
						ResourceType:      "aws_s3_bucket",
						ResourceNamespace: namespace,
					},
				},
			},
		},
	}}}

	ResourceFilter(
		&in,
		func(resource *models.ResourceState) bool {
			if tfplanMeta, ok := resource.Meta["tfplan"].(map[string]interface{}); ok {
				if resourceActions, ok := tfplanMeta["resource_actions"].([]interface{}); ok {
					for _, resourceAction := range resourceActions {
						if str, ok := resourceAction.(string); ok {
							if str == "create" || str == "update" {
								return true
							}
						}
					}
				}
			}
			return false
		},
	)

	expected := models.Results{Results: []models.Result{{
		Input: models.State{
			Resources: map[string]map[string]models.ResourceState{
				"aws_s3_bucket": {
					"aws_s3_bucket.create_bucket": {
						Id:           "aws_s3_bucket.create_bucket",
						ResourceType: "aws_s3_bucket",
						Namespace:    namespace,
						Meta: map[string]interface{}{
							"region": "us-east-1",
							"tfplan": map[string]interface{}{
								"resource_actions": []interface{}{"create"},
							},
						},
						Attributes: map[string]interface{}{
							"acl": "public",
						},
					},
					"aws_s3_bucket.update_bucket": {
						Id:           "aws_s3_bucket.update_bucket",
						ResourceType: "aws_s3_bucket",
						Namespace:    namespace,
						Meta: map[string]interface{}{
							"region": "us-east-1",
							"tfplan": map[string]interface{}{
								"resource_actions": []interface{}{"update"},
							},
						},
						Attributes: map[string]interface{}{
							"acl": "public",
						},
					},
				},
			},
		},
		RuleResults: []models.RuleResults{{
			Id: "SNYK-ABC-01",
			Results: []models.RuleResult{
				{
					Passed:            false,
					ResourceId:        "aws_s3_bucket.create_bucket",
					ResourceType:      "aws_s3_bucket",
					ResourceNamespace: namespace,
				},
				{
					Passed:            false,
					ResourceId:        "aws_s3_bucket.update_bucket",
					ResourceType:      "aws_s3_bucket",
					ResourceNamespace: namespace,
				},
			},
		}},
	}}}

	assert.Equal(t, in, expected)
}
