package policy_test

import (
	"sort"
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/snyk/unified-policy-engine/pkg/policy"
	"github.com/stretchr/testify/assert"
)

// The package names in these test modules are just to get them to parse.

var mod1 = ast.MustParseModule(`
package foo

deny {
	true
}
`)

var mod2 = ast.MustParseModule(`
package bar

deny {
	true
}
`)

var mod3 = ast.MustParseModule(`
package baz

deny {
	true
}
`)

var mod4 = ast.MustParseModule(`
package qux

deny {
	true
}
`)

func TestModuleSetsWithPrefix(t *testing.T) {
	foo := ast.StringTerm("foo")
	bar := ast.StringTerm("bar")
	baz := ast.StringTerm("baz")
	qux := ast.StringTerm("qux")
	testInputs := []struct {
		prefix   ast.Ref
		node     *ast.ModuleTreeNode
		expected []policy.ModuleSet
	}{
		{
			prefix: ast.Ref{foo},
			node: &ast.ModuleTreeNode{
				Children: map[ast.Value]*ast.ModuleTreeNode{
					foo.Value: {
						Modules: []*ast.Module{mod1},
						Children: map[ast.Value]*ast.ModuleTreeNode{
							bar.Value: {
								Modules: []*ast.Module{mod2},
								Children: map[ast.Value]*ast.ModuleTreeNode{
									baz.Value: {
										Modules: []*ast.Module{mod3},
									},
									qux.Value: {
										Modules: []*ast.Module{mod4},
									},
								},
							},
						},
					},
				},
			},
			expected: []policy.ModuleSet{
				{
					Path:    ast.Ref{foo},
					Modules: []*ast.Module{mod1},
				},
				{
					Path:    ast.Ref{foo, bar},
					Modules: []*ast.Module{mod2},
				},
				{
					Path:    ast.Ref{foo, bar, baz},
					Modules: []*ast.Module{mod3},
				},
				{
					Path:    ast.Ref{foo, bar, qux},
					Modules: []*ast.Module{mod4},
				},
			},
		},
		{
			prefix: ast.Ref{foo, bar, baz},
			node: &ast.ModuleTreeNode{
				Children: map[ast.Value]*ast.ModuleTreeNode{
					foo.Value: {
						Modules: []*ast.Module{mod1},
						Children: map[ast.Value]*ast.ModuleTreeNode{
							bar.Value: {
								Modules: []*ast.Module{mod2},
								Children: map[ast.Value]*ast.ModuleTreeNode{
									baz.Value: {
										Modules: []*ast.Module{mod3},
									},
									qux.Value: {
										Modules: []*ast.Module{mod4},
									},
								},
							},
						},
					},
				},
			},
			expected: []policy.ModuleSet{
				{
					Path:    ast.Ref{foo, bar, baz},
					Modules: []*ast.Module{mod3},
				},
			},
		},
		{
			prefix: ast.Ref{foo, bar},
			node: &ast.ModuleTreeNode{
				Children: map[ast.Value]*ast.ModuleTreeNode{
					foo.Value: {
						Children: map[ast.Value]*ast.ModuleTreeNode{
							bar.Value: {
								Modules: []*ast.Module{mod1, mod2, mod3},
								Children: map[ast.Value]*ast.ModuleTreeNode{
									baz.Value: {
										Modules: []*ast.Module{mod4},
									},
								},
							},
						},
					},
				},
			},
			expected: []policy.ModuleSet{
				{
					Path:    ast.Ref{foo, bar},
					Modules: []*ast.Module{mod1, mod2, mod3},
				},
				{
					Path:    ast.Ref{foo, bar, baz},
					Modules: []*ast.Module{mod4},
				},
			},
		},
		{
			prefix: ast.Ref{bar},
			node: &ast.ModuleTreeNode{
				Children: map[ast.Value]*ast.ModuleTreeNode{
					foo.Value: {
						Modules: []*ast.Module{mod1},
					},
					bar.Value: {
						Modules: []*ast.Module{mod2},
						Children: map[ast.Value]*ast.ModuleTreeNode{
							baz.Value: {
								Modules: []*ast.Module{mod3},
							},
							qux.Value: {
								Modules: []*ast.Module{mod4},
							},
						},
					},
				},
			},
			expected: []policy.ModuleSet{
				{
					Path:    ast.Ref{bar},
					Modules: []*ast.Module{mod2},
				},
				{
					Path:    ast.Ref{bar, baz},
					Modules: []*ast.Module{mod3},
				},
				{
					Path:    ast.Ref{bar, qux},
					Modules: []*ast.Module{mod4},
				},
			},
		},
		{
			prefix:   ast.Ref{foo, bar},
			node:     &ast.ModuleTreeNode{},
			expected: []policy.ModuleSet{},
		},
	}
	for _, input := range testInputs {
		output := policy.ModuleSetsWithPrefix(input.prefix, input.node)
		expected := input.expected
		sort.Slice(output, func(i, j int) bool {
			return output[i].Path.String() < output[j].Path.String()
		})
		sort.Slice(expected, func(i, j int) bool {
			return expected[i].Path.String() < expected[j].Path.String()
		})
		// There's an assert.ElementsMatch, but the output is way too verbose when the
		// elements do not match.
		assert.Equal(t, expected, output)
	}
}
