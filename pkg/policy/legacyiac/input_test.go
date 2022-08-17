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
