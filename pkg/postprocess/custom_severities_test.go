package postprocess

import (
	"testing"

	"github.com/stretchr/testify/assert"

	models "github.com/snyk/policy-engine/pkg/models/latest"
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
