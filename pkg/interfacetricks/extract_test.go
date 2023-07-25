package interfacetricks

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type Primitives struct {
	Bool    bool    `json:"bool"`
	Int     int     `json:"int,omitempty"`
	Float64 float64 `json:"float64"`
	String  string  `json:"string"`
}

func TestPrimitives(t *testing.T) {
	p1 := Primitives{}
	p2 := Primitives{}
	PropertyCompareToEncoding(t, Primitives{
		Bool:    true,
		Int:     4,
		Float64: 3.14,
		String:  "Hello, world!",
	}, &p1, &p2)

	p1 = Primitives{}
	p2 = Primitives{}
	PropertyCompareToEncoding(t, Primitives{
		Bool:   false,
		String: "Hello, world!",
	}, &p1, &p2)
}

type Collections struct {
	Slice []Primitives   `json:"slice"`
	Map   map[string]int `json:"map"`
}

func TestCollections(t *testing.T) {
	c1 := Collections{}
	c2 := Collections{}
	PropertyCompareToEncoding(t, Collections{
		Slice: []Primitives{
			{String: "one!"},
			{String: "two!"},
		},
		Map: map[string]int{
			"three": 3,
			"four":  4,
		},
	}, &c1, &c2)
}

func TestCollectionErrors(t *testing.T) {
	stringType := reflect.TypeOf("foo")
	boolType := reflect.TypeOf(true)
	intType := reflect.TypeOf(int(1))
	dst := Collections{}
	errs := Extract(map[string]interface{}{
		"slice": []interface{}{
			int(1), // Error!
			map[string]interface{}{
				"string": "Hello, world!",
				"bool":   "not actually a bool",
			},
		},
	}, &dst)
	require.Equal(t, []error{
		ExtractError{
			SrcPath: []interface{}{"slice", 0},
			SrcType: intType,
			DstType: reflect.TypeOf(Primitives{}),
		},
		ExtractError{
			SrcPath: []interface{}{"slice", 1, "bool"},
			SrcType: stringType,
			DstType: boolType,
		},
	}, errs)
	require.Equal(t, Collections{
		Slice: []Primitives{
			{},
			{String: "Hello, world!"},
		},
	}, dst)
}

// PropertyCompareToEncoding helps testing the Extract function.  We deserialize
// a value twice --- once using a JSON round-trip, and once using our own
// Extract.  We expect the result to be the same.
func PropertyCompareToEncoding(
	t *testing.T,
	src interface{},
	usingJson interface{},
	usingExtract interface{},
) {
	// JSON round-trip
	bytes, err := json.Marshal(src)
	require.NoError(t, err)
	err = json.Unmarshal(bytes, usingJson)
	require.NoError(t, err)

	// First decode to generic interface{}, then Extract.
	var value interface{}
	err = json.Unmarshal(bytes, &value)
	require.NoError(t, err)
	require.Nil(t, Extract(value, usingExtract))

	// Should be the same.
	assert.Equal(t, usingJson, usingExtract)
}
