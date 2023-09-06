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

package policy

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/policy-engine/pkg/input"
)

// TestReferencesFor tests that we obtain only the expected references.
func TestReferencesFor(t *testing.T) {
	meta1 := Metadata{}
	err := json.Unmarshal([]byte(`{
	"references": {
		"general": [
			{
				"title": "Some doc",
				"url": "https://example.com"
			}
		],
		"terraform": [
			{
				"title": "Resource: aws_s3_bucket",
				"url": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket"
			}
		],
		"cloudformation": [
			{
				"title": "AWS::S3::Bucket",
				"url": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
			}
		]
	}
}`), &meta1)
	assert.NoError(t, err)
	assert.Equal(t,
		meta1.ReferencesFor("cfn"),
		[]MetadataReference{
			{
				Title: "Some doc",
				URL:   "https://example.com",
			},
			{
				Title: "AWS::S3::Bucket",
				URL:   "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html",
			},
		},
	)
}

func TestRemediationFor(t *testing.T) {
	m := Metadata{
		Remediation: map[string]string{
			"arm":            "remediation for arm",
			"cloudformation": "remediation for cloudformation",
			"console":        "remediation for console",
			"kubernetes":     "remediation for kubernetes",
			"terraform":      "remediation for terraform",
		},
	}

	assert.Equal(t, m.RemediationFor(input.Arm.Name), "remediation for arm")
	assert.Equal(t, m.RemediationFor(input.CloudFormation.Name), "remediation for cloudformation")
	assert.Equal(t, m.RemediationFor(input.CloudScan.Name), "remediation for console")
	assert.Equal(t, m.RemediationFor(input.Kubernetes.Name), "remediation for kubernetes")
	assert.Equal(t, m.RemediationFor(input.TerraformHCL.Name), "remediation for terraform")
	assert.Equal(t, m.RemediationFor(input.TerraformState.Name), "remediation for terraform")
	assert.Equal(t, m.RemediationFor(input.TerraformPlan.Name), "remediation for terraform")
}
