// Copyright 2022 Snyk Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This module contains utilities for parsing and traversing everything in a
// configuration tree.
package hcl_interpreter

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

type Term struct {
	// One of `expr` or `attrs/blocks` will be set.
	expr   *hcl.Expression
	attrs  map[string]hcl.Expression
	blocks map[string][]Term

	// Meta-expressions
	count *hcl.Expression
}

func TermFromExpr(expr hcl.Expression) Term {
	return Term{
		expr: &expr,
	}
}

func TermFromBody(body hcl.Body) Term {
	switch b := body.(type) {
	case *hclsyntax.Body:
		return termFromBlock(b)
	default:
		return termFromJustAttributes(body)
	}
}

func termFromJustAttributes(body hcl.Body) Term {
	attrs := map[string]hcl.Expression{}
	attributes, _ := body.JustAttributes()
	for _, attribute := range attributes {
		attrs[attribute.Name] = attribute.Expr
	}
	return Term{
		attrs:  attrs,
		blocks: map[string][]Term{},
	}
}

func termFromBlock(body *hclsyntax.Body) Term {
	attrs := map[string]hcl.Expression{}
	for _, attribute := range body.Attributes {
		attrs[attribute.Name] = attribute.Expr
	}

	blocks := map[string][]Term{}
	for _, block := range body.Blocks {
		if _, ok := blocks[block.Type]; !ok {
			blocks[block.Type] = []Term{}
		}
		blocks[block.Type] = append(blocks[block.Type], TermFromBody(block.Body))
	}

	return Term{
		attrs:  attrs,
		blocks: blocks,
	}
}

func (t Term) WithCount(expr hcl.Expression) Term {
	t.count = &expr
	return t
}

func (t Term) VisitExpressions(f func(hcl.Expression)) {
	if t.expr != nil {
		f(*t.expr)
	} else {
		for _, attr := range t.attrs {
			f(attr)
		}
		for _, blocks := range t.blocks {
			for _, block := range blocks {
				block.VisitExpressions(f)
			}
		}
		if t.count != nil {
			f(*t.count)
		}
	}
}

func (t Term) Dependencies() []hcl.Traversal {
	dependencies := []hcl.Traversal{}
	t.VisitExpressions(func(e hcl.Expression) {
		dependencies = append(dependencies, e.Variables()...)
	})
	return dependencies
}

func (t Term) evaluateExpr(
	evalExpr func(expr hcl.Expression, extraVars interface{}) (cty.Value, hcl.Diagnostics),
) (cty.Value, hcl.Diagnostics) {
	if t.expr != nil {
		return evalExpr(*t.expr, EmptyObjectValTree())
	} else {
		obj := map[string]cty.Value{}
		diagnostics := hcl.Diagnostics{}

		for k, attr := range t.attrs {
			val, diags := evalExpr(attr, EmptyObjectValTree())
			diagnostics = append(diagnostics, diags...)
			obj[k] = val
		}

		blists := map[string][]cty.Value{}
		for k, blocks := range t.blocks {
			blists[k] = []cty.Value{}
			for _, block := range blocks {
				val, diags := block.Evaluate(evalExpr)
				diagnostics = append(diagnostics, diags...)
				blists[k] = append(blists[k], val)
			}
		}
		for k, blocks := range blists {
			obj[k] = cty.TupleVal(blocks)
		}

		return cty.ObjectVal(obj), diagnostics
	}
}

func (t Term) Evaluate(
	evalExpr func(expr hcl.Expression, extraVars interface{}) (cty.Value, hcl.Diagnostics),
) (cty.Value, hcl.Diagnostics) {
	if t.count != nil {
		// Helper
		parseCount := func(val cty.Value) *int64 {
			if val.IsNull() || !val.IsKnown() {
				// An unknown variable prompts the user to enter a value.  This
				// could be how many resources we want to create.  Just create one
				// so we can check it for misconfigurations.
				count := int64(1)
				return &count
			} else if val.Type() == cty.Number {
				big := val.AsBigFloat()
				if big.IsInt() {
					count, _ := big.Int64()
					return &count
				}
			}
			return nil
		}

		diagnostics := hcl.Diagnostics{}
		countVal, diags := evalExpr(*t.count, EmptyObjectValTree())
		diagnostics = append(diagnostics, diags...)
		if count := parseCount(countVal); count != nil {
			arr := []cty.Value{}
			for i := int64(0); i < *count; i++ {
				val, diags := t.evaluateExpr(func(e hcl.Expression, v interface{}) (cty.Value, hcl.Diagnostics) {
					v = MergeValTree(v, SingletonValTree(LocalName{"count", "index"}, cty.NumberIntVal(i)))
					return evalExpr(e, v)
				})
				diagnostics = append(diagnostics, diags...)
				arr = append(arr, val)
			}
			return cty.TupleVal(arr), diagnostics
		}
	}

	return t.evaluateExpr(evalExpr)
}

// Attr retrieves a term attribute, or nil if it doesn't exist, or the term
// doesn't have attributes.
func (t Term) Attributes() map[string]Term {
	attrs := map[string]Term{}
	for k, expr := range t.attrs {
		attrs[k] = TermFromExpr(expr)
	}
	return attrs
}

type TermTree struct {
	modules map[string]*termLocalTree
}

type termLocalTree struct {
	term     *Term
	children map[string]*termLocalTree
}

func NewTermTree() *TermTree {
	return &TermTree{
		modules: map[string]*termLocalTree{},
	}
}

func (t *TermTree) AddTerm(name FullName, term Term) {
	moduleKey := ModuleNameToString(name.Module)
	if _, ok := t.modules[moduleKey]; !ok {
		t.modules[moduleKey] = &termLocalTree{}
	}

	t.modules[moduleKey].addTerm(name.Local, term)
}

func (t *termLocalTree) addTerm(name LocalName, term Term) {
	if len(name) == 0 {
		t.term = &term
	} else {
		if t.children == nil {
			t.children = map[string]*termLocalTree{}
		}
		if head, ok := name[0].(string); ok {
			if _, ok := t.children[head]; !ok {
				t.children[head] = &termLocalTree{}
			}
			t.children[head].addTerm(name[1:], term)
		} else {
			panic("TODO: adding int-based term to termLocalTree??")
		}
	}
}

func (t *TermTree) LookupByPrefix(name FullName) (*FullName, *Term) {
	moduleKey := ModuleNameToString(name.Module)
	if tree, ok := t.modules[moduleKey]; ok {
		prefix, term := tree.lookupByPrefix(name.Local)
		if term != nil {
			return &FullName{name.Module, prefix}, term
		}
	}

	return nil, nil
}

func (t *termLocalTree) lookupByPrefix(name LocalName) (LocalName, *Term) {
	if t.term != nil {
		return LocalName{}, t.term
	} else if len(name) > 0 {
		if head, ok := name[0].(string); ok {
			if child, ok := t.children[head]; ok {
				prefix, term := child.lookupByPrefix(name[1:])
				if term != nil {
					prefix = append(LocalName{head}, prefix...)
					return prefix, term
				}
			}
		}
	}

	return nil, nil
}

func (t *TermTree) VisitTerms(f func(name FullName, term Term)) {
	for moduleKey, module := range t.modules {
		moduleFullName, err := StringToFullName(moduleKey)
		if err != nil {
			panic(err)
		}
		moduleName := moduleFullName.Module
		module.visitTerms(FullName{moduleName, LocalName{}}, f)
	}
}

func (t *termLocalTree) visitTerms(name FullName, f func(FullName, Term)) {
	if t.term != nil {
		f(name, *t.term)
	} else {
		for key, child := range t.children {
			child.visitTerms(name.AddKey(key), f)
		}
	}
}
