package rego

import (
	"context"
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/stretchr/testify/assert"
)

func TestQuery1(t *testing.T) {
	ctx := context.Background()
	modules := map[string]*ast.Module{
		"example.rego": ast.MustParseModule(`
package example

people = [
	{"name": "Sam", "age": 30, "aliases": ["Kim", "Tom"], "attributes": {"teeth": 32}, "hungry": true},
	{"name": "Kim", "age": 40, "aliases": ["Sam", "Tim"], "attributes": {"teeth": 28}, "hungry": false},
]`),
	}

	state, err := NewState(Options{
		Modules: modules,
	})
	assert.NoError(t, err)

	type Person struct {
		Name       string      `rego:"name"`
		Age        int         `rego:"age"`
		Aliases    []string    `rego:"aliases"`
		Attributes interface{} `rego:"attributes"`
		Hungry     bool        `rego:"hungry"`
		Nonexist   string      `rego:"nonexist"`
	}

	var people []Person
	err = state.Query(
		ctx,
		Query{Query: "data.example.people[_]"},
		func(val ast.Value) error {
			var person Person
			if err := Bind(val, &person); err != nil {
				return err
			}
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
				Attributes: map[string]interface{}{"teeth": 32.0},
				Hungry:     true,
				Nonexist:   "",
			},
			{
				Name:       "Kim",
				Age:        40,
				Aliases:    []string{"Sam", "Tim"},
				Attributes: map[string]interface{}{"teeth": 28.0},
				Hungry:     false,
				Nonexist:   "",
			},
		},
		people,
	)
}

func TestQueryStrict(t *testing.T) {
	ctx := context.Background()
	modules := map[string]*ast.Module{
		"example.rego": ast.MustParseModule(`
package example

people = [
	{"name": "Sam", "age": 30},
	{"name": "Kim", "age": 40},
]`),
	}

	state, err := NewState(Options{
		Modules: modules,
	})
	assert.NoError(t, err)

	var numbers []int
	assert.NoError(t, state.Query(
		ctx,
		Query{Query: "data.example.people[_].age + 1"},
		func(val ast.Value) error {
			var number int
			if err := Bind(val, &number); err != nil {
				return err
			}
			numbers = append(numbers, number)
			return nil
		},
	))
	assert.Equal(t, []int{31, 41}, numbers)
}

func TestQueryTimeout(t *testing.T) {
	ctx := context.Background()
	modules := map[string]*ast.Module{
		"example.rego": ast.MustParseModule(`
package example

people = [
	{"name": "Sam", "age": 30},
	{"name": "Kim", "age": 40},
]`),
	}

	state, err := NewState(Options{
		Modules: modules,
	})
	assert.NoError(t, err)

	err = state.Query(
		ctx,
		Query{
			Query:   "data.example.people[_]",
			Timeout: 1,
		},
		func(val ast.Value) error {
			return nil
		},
	)
	assert.ErrorIs(t, err, ErrQueryTimedOut)
}
