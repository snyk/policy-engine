package rego

import (
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/stretchr/testify/assert"
)

type Primitives struct {
	Bool    bool    `rego:"bool"`
	Int     int     `rego:"int"`
	Float64 float64 `rego:"float64"`
	String  string  `rego:"string"`
}

func TestBindPrimitives(t *testing.T) {
	var actual Primitives
	assert.NoError(t, Bind(ast.NewObject(
		[2]*ast.Term{ast.StringTerm("bool"), ast.BooleanTerm(true)},
		[2]*ast.Term{ast.StringTerm("int"), ast.FloatNumberTerm(42)},
		[2]*ast.Term{ast.StringTerm("float64"), ast.FloatNumberTerm(3.14)},
		[2]*ast.Term{ast.StringTerm("string"), ast.StringTerm("Hello, world!")},
	), &actual))
	assert.Equal(t,
		Primitives{
			Bool:    true,
			Int:     42,
			String:  "Hello, world!",
			Float64: 3.14,
		},
		actual,
	)
}
