// Copyright 2022 Snyk Ltd
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

package interfacetricks

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEqual(t *testing.T) {
	assert.True(t, Equal(3, 1+2))
	assert.True(t, Equal(
		[]interface{}{
			map[string]interface{}{
				"foo": "bar",
				"qux": nil,
			},
			2 + 1,
		},
		[]interface{}{
			map[string]interface{}{
				"foo": "bar",
				"qux": nil,
			},
			3,
		},
	))

	assert.False(t, Equal(
		[]interface{}{
			map[string]interface{}{
				"foo": "qux",
			},
			2 + 1,
		},
		[]interface{}{
			map[string]interface{}{
				"foo": "bar",
			},
			3,
		},
	))

	assert.False(t, Equal(
		[]interface{}{
			map[string]interface{}{
				"qux": "bar",
			},
			2 + 1,
		},
		[]interface{}{
			map[string]interface{}{
				"foo": "bar",
			},
			3,
		},
	))
}
