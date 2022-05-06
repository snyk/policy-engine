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
