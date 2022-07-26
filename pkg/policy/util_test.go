package policy

import (
	"sort"
	"testing"

	"github.com/open-policy-agent/opa/ast"
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
		expected []ModuleSet
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
			expected: []ModuleSet{
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
			expected: []ModuleSet{
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
			expected: []ModuleSet{
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
			expected: []ModuleSet{
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
			expected: []ModuleSet{},
		},
	}
	for _, input := range testInputs {
		output := moduleSetsWithPrefix(input.prefix, input.node)
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

func TestExtractModuleSets(t *testing.T) {
	data := ast.DefaultRootDocument
	rules := ast.StringTerm("rules")
	ruleName := ast.StringTerm("some_rule_name")
	ruleID := ast.StringTerm("RULE_ID")
	terraform := ast.StringTerm("terraform")
	schemas := ast.StringTerm("schemas")
	kubernetes := ast.StringTerm("kubernetes")

	for _, tc := range []struct {
		name     string
		node     *ast.ModuleTreeNode
		expected []ModuleSet
	}{
		{
			name:     "empty tree",
			node:     &ast.ModuleTreeNode{},
			expected: []ModuleSet{},
		},
		{
			name: "current policy spec",
			node: &ast.ModuleTreeNode{
				Children: map[ast.Value]*ast.ModuleTreeNode{
					data.Value: {
						Children: map[ast.Value]*ast.ModuleTreeNode{
							rules.Value: {
								Children: map[ast.Value]*ast.ModuleTreeNode{
									ruleID.Value: {
										Children: map[ast.Value]*ast.ModuleTreeNode{
											terraform.Value: {
												Modules: []*ast.Module{mod1},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: []ModuleSet{
				{
					Path:    ast.Ref{data, rules, ruleID, terraform},
					Modules: []*ast.Module{mod1},
				},
			},
		},
		{
			name: "legacy fugue policy spec",
			node: &ast.ModuleTreeNode{
				Children: map[ast.Value]*ast.ModuleTreeNode{
					data.Value: {
						Children: map[ast.Value]*ast.ModuleTreeNode{
							rules.Value: {
								Children: map[ast.Value]*ast.ModuleTreeNode{
									ruleName.Value: {
										Modules: []*ast.Module{mod1},
									},
								},
							},
						},
					},
				},
			},
			expected: []ModuleSet{
				{
					Path:    ast.Ref{data, rules, ruleName},
					Modules: []*ast.Module{mod1},
				},
			},
		},
		{
			name: "legacy iac policy spec",
			node: &ast.ModuleTreeNode{
				Children: map[ast.Value]*ast.ModuleTreeNode{
					data.Value: {
						Children: map[ast.Value]*ast.ModuleTreeNode{
							schemas.Value: {
								Children: map[ast.Value]*ast.ModuleTreeNode{
									terraform.Value: {
										Modules: []*ast.Module{mod1},
										Children: map[ast.Value]*ast.ModuleTreeNode{
											// This module should not be loaded
											kubernetes.Value: {
												Modules: []*ast.Module{mod2},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: []ModuleSet{
				{
					Path:    ast.Ref{data, schemas, terraform},
					Modules: []*ast.Module{mod1},
				},
			},
		},
		{
			name: "legacy iac custom policy spec",
			node: &ast.ModuleTreeNode{
				Children: map[ast.Value]*ast.ModuleTreeNode{
					data.Value: {
						Children: map[ast.Value]*ast.ModuleTreeNode{
							rules.Value: {
								Modules: []*ast.Module{mod1},
							},
						},
					},
				},
			},
			expected: []ModuleSet{
				{
					Path:    ast.Ref{data, rules},
					Modules: []*ast.Module{mod1},
				},
			},
		},
		{
			name: "all policy specs",
			node: &ast.ModuleTreeNode{
				Children: map[ast.Value]*ast.ModuleTreeNode{
					data.Value: {
						Children: map[ast.Value]*ast.ModuleTreeNode{
							rules.Value: {
								Modules: []*ast.Module{mod1},
								Children: map[ast.Value]*ast.ModuleTreeNode{
									ruleID.Value: {
										Children: map[ast.Value]*ast.ModuleTreeNode{
											terraform.Value: {
												Modules: []*ast.Module{mod2},
											},
										},
									},
									ruleName.Value: {
										Modules: []*ast.Module{mod3},
									},
								},
							},
							schemas.Value: {
								Children: map[ast.Value]*ast.ModuleTreeNode{
									terraform.Value: {
										Modules: []*ast.Module{mod4},
									},
								},
							},
						},
					},
				},
			},
			expected: []ModuleSet{
				{
					Path:    ast.Ref{data, rules},
					Modules: []*ast.Module{mod1},
				},
				{
					Path:    ast.Ref{data, rules, ruleID, terraform},
					Modules: []*ast.Module{mod2},
				},
				{
					Path:    ast.Ref{data, rules, ruleName},
					Modules: []*ast.Module{mod3},
				},
				{
					Path:    ast.Ref{data, schemas, terraform},
					Modules: []*ast.Module{mod4},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := ExtractModuleSets(tc.node)
			expected := tc.expected
			sort.Slice(output, func(i, j int) bool {
				return output[i].Path.String() < output[j].Path.String()
			})
			sort.Slice(expected, func(i, j int) bool {
				return expected[i].Path.String() < expected[j].Path.String()
			})
			// There's an assert.ElementsMatch, but the output is way too verbose when the
			// elements do not match.
			assert.Equal(t, expected, output)
		})
	}
}

func TestScopeMatches(t *testing.T) {
	for _, tc := range []struct {
		name          string
		query         map[string]string
		input         map[string]interface{}
		expectedMatch bool
	}{
		{
			name:          "empty scope matches empty scope",
			query:         map[string]string{},
			input:         map[string]interface{}{},
			expectedMatch: true,
		},
		{
			name:          "empty scope matches any scope",
			query:         map[string]string{},
			input:         map[string]interface{}{"filename": "foo.tf", "git_branch": "main"},
			expectedMatch: true,
		},
		{
			name:          "identical scopes match",
			query:         map[string]string{"filename": "foo.tf", "git_branch": "main"},
			input:         map[string]interface{}{"filename": "foo.tf", "git_branch": "main"},
			expectedMatch: true,
		},
		{
			name:          "matches when all query fields match but input has more fields",
			query:         map[string]string{"filename": "foo.tf"},
			input:         map[string]interface{}{"filename": "foo.tf", "git_branch": "main"},
			expectedMatch: true,
		},
		{
			name:          "doesn't match when queried field differs",
			query:         map[string]string{"filename": "foo.tf"},
			input:         map[string]interface{}{"filename": "bar.tf"},
			expectedMatch: false,
		},
		{
			name:          "query of * matches any present value",
			query:         map[string]string{"region": "*"},
			input:         map[string]interface{}{"region": "us-east-1"},
			expectedMatch: true,
		},
		{
			name:          "query of empty string matches any present value",
			query:         map[string]string{"region": ""},
			input:         map[string]interface{}{"region": "us-east-1"},
			expectedMatch: true,
		},
		{
			name:          "query of * requires value to be present",
			query:         map[string]string{"region": "*"},
			input:         map[string]interface{}{},
			expectedMatch: false,
		},
		{
			name:          "query of empty string requires value to be present",
			query:         map[string]string{"region": ""},
			input:         map[string]interface{}{},
			expectedMatch: false,
		},
		{
			name:          "overall match requires all query fields to match input fields",
			query:         map[string]string{"region": "us-east-1", "account": "foo"},
			input:         map[string]interface{}{"region": "us-east-1", "account": "bar"},
			expectedMatch: false,
		},
		{
			name:          "overall match requires all query fields to at least be present in input",
			query:         map[string]string{"region": "us-east-1", "account": "foo"},
			input:         map[string]interface{}{"region": "us-east-1", "something_else": "foo"},
			expectedMatch: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matches := ScopeMatches(tc.query, tc.input)
			assert.Equal(t, tc.expectedMatch, matches)
		})
	}
}
