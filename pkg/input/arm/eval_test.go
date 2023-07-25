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

func TestEvalTemplateStrings(t *testing.T) {
	for _, tc := range []struct {
		name     string
		input    string
		expected interface{}
	}{
		{
			name:     "returns inputs that are not ARM expressions",
			input:    "just a plain string, that is [not] and expression",
			expected: "just a plain string, that is [not] and expression",
		},
		{
			name:     "replaces escape sequences inside ARM expressions",
			input:    "['[[string literal in brackets]], ''escaped single quotes''']",
			expected: "[string literal in brackets], 'escaped single quotes'",
		},
		{
			name:     "concat string literals",
			input:    "[concat('foo', '-bar')]",
			expected: "foo-bar",
		},
		{
			name:     "attribute access",
			input:    "[resourceGroup().location]",
			expected: "stub-location",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evalCtx := &EvaluationContext{Functions: DiscoveryBuiltinFunctions(nil)}
			val, err := evalCtx.EvaluateTemplateString(tc.input)
			require.NoError(t, err)
			require.Equal(t, tc.expected, val)
		})
	}
}
