// Copyright 2022-2023 Snyk Ltd
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
	"testing"

	"github.com/snyk/policy-engine/pkg/input"
	"github.com/stretchr/testify/assert"
)

func TestLegacyIaCInputType(t *testing.T) {
	for _, tc := range []struct {
		pkg      string
		expected *input.Type
	}{
		{
			pkg:      "data.schemas.arm",
			expected: input.Arm,
		},
		{
			pkg:      "data.schemas.cloudformation",
			expected: input.CloudFormation,
		},
		{
			pkg:      "data.schemas.kubernetes",
			expected: input.Kubernetes,
		},
		{
			pkg:      "data.schemas.terraform",
			expected: input.Terraform,
		},
		{
			pkg:      "data.schemas.terraform.kubernetes",
			expected: input.Terraform,
		},
		{
			pkg:      "data.schemas.terraform.azure",
			expected: input.Terraform,
		},
		{
			pkg:      "data.rules",
			expected: input.Any,
		},
	} {
		t.Run(tc.pkg, func(t *testing.T) {
			policy := LegacyIaCPolicy{
				BasePolicy: &BasePolicy{
					pkg:       tc.pkg,
					inputType: input.Any,
				},
			}
			assert.Equal(t, tc.expected, policy.inputType())
		})
	}
}
