// © 2023 Snyk Limited All rights reserved.
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

func TestApplyCustomSeverities(t *testing.T) {
	namespace := "golden_test/tfplan/resource-changes/plan.json"
	in := models.Results{Results: []models.Result{{
		RuleResults: []models.RuleResults{
			{
				Id: "SNYK-ABC-01",
				Results: []models.RuleResult{
					{
						Passed:            false,
						ResourceId:        "aws_s3_bucket.bucket",
						ResourceType:      "aws_s3_bucket",
						ResourceNamespace: namespace,
						Severity:          "High",
					},
				},
			},
			{
				Id: "SNYK-ABC-02",
				Results: []models.RuleResult{
					{
						Passed:            false,
						ResourceId:        "aws_s3_bucket.bucket",
						ResourceType:      "aws_s3_bucket",
						ResourceNamespace: namespace,
						Severity:          "High",
					},
				},
			},
			{
				Id: "SNYK-ABC-03",
				Results: []models.RuleResult{
					{
						Passed:            false,
						ResourceId:        "aws_s3_bucket.bucket",
						ResourceType:      "aws_s3_bucket",
						ResourceNamespace: namespace,
						Severity:          "High",
					},
				},
			},
		},
	}}}
	customSeverities := CustomSeverities{
		"SNYK-ABC-01": "None",
		"SNYK-ABC-02": "Low",
	}
	expected := models.Results{Results: []models.Result{{
		RuleResults: []models.RuleResults{
			{
				Id: "SNYK-ABC-02",
				Results: []models.RuleResult{
					{
						Passed:            false,
						ResourceId:        "aws_s3_bucket.bucket",
						ResourceType:      "aws_s3_bucket",
						ResourceNamespace: namespace,
						Severity:          "Low",
					},
				},
			},
			{
				Id: "SNYK-ABC-03",
				Results: []models.RuleResult{
					{
						Passed:            false,
						ResourceId:        "aws_s3_bucket.bucket",
						ResourceType:      "aws_s3_bucket",
						ResourceNamespace: namespace,
						Severity:          "High",
					},
				},
			},
		},
	}}}
	ApplyCustomSeverities(&in, customSeverities)
	assert.Equal(t, expected, in)
}
