package regobind

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/stretchr/testify/assert"
)

func TestBind3(t *testing.T) {
	ctx := context.Background()
	modules := map[string]*ast.Module{
		"example.rego": ast.MustParseModule(`
package example

people = [
	{"name": "Sam", "age": 30, "aliases": ["Kim", "Tom"], "attributes": {"teeth": 32}, "hungry": true},
	{"name": "Kim", "age": 40, "aliases": ["Sam", "Tim"], "attributes": {"teeth": 28}, "hungry": false},
]`),
	}

	state, err := NewState(&Options{
		Modules: modules,
	})
	assert.NoError(t, err)

	var people []Person
	var person Person
	err = state.Query(
		ctx,
		&QueryOptions{},
		"data.example.people[_]",
		&person,
		func() error {
			people = append(people, person)
			return nil
		},
	)
	assert.NoError(t, err)
	assert.Equal(t,
		[]Person{
			{
				Name:       "Sam",
				Age:        30,
				Aliases:    []string{"Kim", "Tom"},
				Attributes: map[string]interface{}{"teeth": json.Number("32")},
				Hungry:     true,
				Nonexist:   "",
			},
			{
				Name:       "Kim",
				Age:        40,
				Aliases:    []string{"Sam", "Tim"},
				Attributes: map[string]interface{}{"teeth": json.Number("28")},
				Hungry:     false,
				Nonexist:   "",
			},
		},
		people,
	)
}
