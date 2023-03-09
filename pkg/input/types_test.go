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

package input_test

import (
	"testing"

	"github.com/snyk/policy-engine/pkg/input"
	"github.com/stretchr/testify/assert"
)

func TestTypeEqual(t *testing.T) {
	for _, tc := range []struct {
		name     string
		a        *input.Type
		b        *input.Type
		expected bool
	}{
		{
			name:     "pointer equal",
			a:        input.Terraform,
			b:        input.Terraform,
			expected: true,
		},
		{
			name:     "simple equal",
			a:        &input.Type{Name: "foo"},
			b:        &input.Type{Name: "foo"},
			expected: true,
		},
		{
			name: "equal with aliases",
			a: &input.Type{
				Name:    "foo",
				Aliases: []string{"f", "bar"},
			},
			b: &input.Type{
				Name:    "foo",
				Aliases: []string{"f", "bar"},
			},
			expected: true,
		},
		{
			name: "equal with children",
			a: &input.Type{
				Name: "foo",
				Children: input.Types{
					&input.Type{Name: "bar"},
				},
			},
			b: &input.Type{
				Name: "foo",
				Children: input.Types{
					&input.Type{Name: "bar"},
				},
			},
			expected: true,
		},
		{
			name:     "simple non-equal",
			a:        &input.Type{Name: "foo"},
			b:        &input.Type{Name: "bar"},
			expected: false,
		},
		{
			name: "non-equal from aliases",
			a: &input.Type{
				Name:    "foo",
				Aliases: []string{"f", "bar"},
			},
			b: &input.Type{
				Name:    "foo",
				Aliases: []string{"f", "baz"},
			},
			expected: false,
		},
		{
			name: "non-equal from children",
			a: &input.Type{
				Name: "foo",
				Children: input.Types{
					&input.Type{Name: "bar"},
				},
			},
			b: &input.Type{
				Name: "foo",
				Children: input.Types{
					&input.Type{Name: "baz"},
				},
			},
			expected: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.a.Equals(tc.b))
		})
	}
}
