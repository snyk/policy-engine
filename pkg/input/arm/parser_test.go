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

package arm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		name     string
		input    string
		expected expression
	}{
		{
			name:     "returns simple expression for a single scalar",
			input:    "'hi'",
			expected: stringLiteralExpr("hi"),
		},
		{
			name:     "returns expression for single function call (no args)",
			input:    "resourceGroup()",
			expected: functionExpr{name: "resourceGroup"},
		},
		{
			name:  "returns expression for single function call (1 arg)",
			input: "bork('foo')",
			expected: functionExpr{
				name: "bork",
				args: []expression{stringLiteralExpr("foo")},
			},
		},
		{
			name:  "returns expression for single function call (2 args)",
			input: "concat('foo', 'bar')",
			expected: functionExpr{
				name: "concat",
				args: []expression{stringLiteralExpr("foo"), stringLiteralExpr("bar")},
			},
		},
		{
			name:  "returns expression for nested function calls",
			input: "concat(resourceGroup(), '-thing')",
			expected: functionExpr{
				name: "concat",
				args: []expression{
					functionExpr{name: "resourceGroup"},
					stringLiteralExpr("-thing"),
				},
			},
		},
		{
			name:  "returns expression for property access",
			input: "resourceGroup().location",
			expected: propertyExpr{
				obj:      functionExpr{name: "resourceGroup"},
				property: "location",
			},
		},
		{
			name:  "returns expression for nested property access",
			input: "resourceGroup().foo.bar.baz",
			expected: propertyExpr{
				obj: propertyExpr{
					obj: propertyExpr{
						obj:      functionExpr{name: "resourceGroup"},
						property: "foo",
					},
					property: "bar",
				},
				property: "baz",
			},
		},
		{
			name:  "supports arrays",
			input: "[[], ['foo'], [resourceGroup().location, 'bar']]",
			expected: arrayExpr([]expression{
				arrayExpr(nil),
				arrayExpr([]expression{stringLiteralExpr("foo")}),
				arrayExpr([]expression{
					propertyExpr{
						obj:      functionExpr{name: "resourceGroup"},
						property: "location",
					},
					stringLiteralExpr("bar"),
				}),
			}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tokens, err := tokenize(tc.input)
			require.NoError(t, err)
			result, err := parse(tokens)
			require.NoError(t, err)
			require.Equal(t, tc.expected, result)
		})
	}
}
