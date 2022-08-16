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
