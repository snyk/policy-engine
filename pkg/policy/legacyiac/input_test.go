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

func FuzzParsePath(f *testing.F) {
	for _, tc := range []string{
		"resources[0]",
		"resources[0].properties.some_property",
		"resource.some_type[some_id].some_property",
		"input.resource.some_type[some_id].some_property",
		`resource.some_type["some_id"].some_property`,
		`resource.some_type['some_id'].some_property`,
		`resource["some_id.some_other_id"]`,
		`resource['"some_id.some_other_id"']`,
		`resource[[some_id][some_other_id]]`,
		`resource\.some_id`,
		`"resource\"some_id"`,
	} {
		f.Add(tc)
	}

	f.Fuzz(func(t *testing.T, a string) {
		parsePath(a)
	})
}
