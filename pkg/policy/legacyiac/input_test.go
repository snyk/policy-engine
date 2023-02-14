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

package legacyiac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsePath(t *testing.T) {
	for _, tc := range []struct {
		msg      string
		expected []interface{}
	}{
		{
			msg:      "resources[0]",
			expected: []interface{}{"resources", 0},
		},
		{
			msg:      "resources[0].properties.some_property",
			expected: []interface{}{"resources", 0, "properties", "some_property"},
		},
		{
			msg:      "resource.some_type[some_id].some_property",
			expected: []interface{}{"resource", "some_type", "some_id", "some_property"},
		},
		{
			msg:      "input.resource.some_type[some_id].some_property",
			expected: []interface{}{"resource", "some_type", "some_id", "some_property"},
		},
		{
			msg:      `resource.some_type["some_id"].some_property`,
			expected: []interface{}{"resource", "some_type", "some_id", "some_property"},
		},
		{
			msg:      `resource.some_type['some_id'].some_property`,
			expected: []interface{}{"resource", "some_type", "some_id", "some_property"},
		},
		{
			msg:      `resource["some_id.some_other_id"]`,
			expected: []interface{}{"resource", "some_id.some_other_id"},
		},
		{
			msg:      `resource['"some_id.some_other_id"']`,
			expected: []interface{}{"resource", `"some_id.some_other_id"`},
		},
		{
			msg:      `resource[[some_id][some_other_id]]`,
			expected: []interface{}{"resource", "some_id", "some_other_id"},
		},
		{
			msg:      `resource\.some_id`,
			expected: []interface{}{"resource.some_id"},
		},
		{
			msg:      `"resource\"some_id"`,
			expected: []interface{}{`resource"some_id`},
		},
	} {
		t.Run(tc.msg, func(t *testing.T) {
			assert.Equal(t, tc.expected, parsePath(tc.msg))
		})
	}
}
