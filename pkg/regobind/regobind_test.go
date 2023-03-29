package regobind

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown"
	"github.com/stretchr/testify/assert"
)

func TestBind(t *testing.T) {
	ctx := context.Background()
	modules := map[string]*ast.Module{
		"example.rego": ast.MustParseModule(`
package example

people = [
	{"name": "Sam", "age": 30},
	{"name": "Kim", "age": 40},
]`),
	}

	compiler := ast.NewCompiler()
	compiler.Compile(modules)
	assert.Len(t, compiler.Errors, 0)

	query := ast.MustParseBody(`x = data.example.people[_].age + 1`)

	q := topdown.NewQuery(query).
		WithCompiler(compiler)
	err := q.Iter(ctx, func(qr topdown.QueryResult) error {
		fmt.Fprintf(os.Stderr, "============================\n")
		for k, term := range qr {
			fmt.Fprintf(os.Stderr, "TERM %s: %s\n", k, term.String())
			fmt.Fprintf(os.Stderr, "TERM %s [val]: %s\n", k, term.Value.String())

			json, err := ast.JSON(term.Value)
			assert.NoError(t, err)
			fmt.Fprintf(os.Stderr, "TERM %s [json]: %v\n", k, json)
		}
		for i, expr := range query {
			fmt.Fprintf(os.Stderr, "EXPR %d: %s\n", i, expr.String())
			if expr.Generated {
    			continue
			}
		}
		return nil
	})
	assert.NoError(t, err)
	t.Fatalf("%s", "bad stuff happened")
}
