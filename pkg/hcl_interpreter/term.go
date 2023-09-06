// © 2022-2023 Snyk Limited All rights reserved.
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
	count    *hcl.Expression
	forEach  *hcl.Expression
	iterator string
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

func termFromDynamicBlock(body *hclsyntax.Body, defaultIterator string) Term {
	// Pull out content
	term := TermFromBody(body)
	for _, b := range body.Blocks {
		if b.Type == "content" {
			term = termFromBlock(b.Body)
		}
	}

	// Pull out iterator
	term.iterator = defaultIterator
	if iterator, ok := body.Attributes["iterator"]; ok {
		expr := iterator.Expr
		vars := expr.Variables()
		if len(vars) == 1 && !vars[0].IsRelative() {
			term.iterator = vars[0].RootName()
		}
	}

	// Pull out for_each
	var forEach hcl.Expression = body.Attributes["for_each"].Expr
	term.forEach = &forEach

	return term
}

func termFromBlock(body *hclsyntax.Body) Term {
	attrs := map[string]hcl.Expression{}
	for _, attribute := range body.Attributes {
		attrs[attribute.Name] = attribute.Expr
	}

	blocks := map[string][]Term{}
	for _, block := range body.Blocks {
		blockType := block.Type
		if _, ok := blocks[blockType]; !ok {
			blocks[blockType] = []Term{}
		}
		var blockTerm Term
		if block.Type == "dynamic" && len(block.Labels) > 0 {
			blockType = block.Labels[0]
			blockTerm = termFromDynamicBlock(block.Body, blockType)
		} else {
			blockTerm = TermFromBody(block.Body)
		}
		blocks[blockType] = append(blocks[blockType], blockTerm)
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

func (t Term) WithForEach(iterator string, expr hcl.Expression) Term {
	t.forEach = &expr
	t.iterator = iterator
	return t
}

// shallowVisitExpressions visits all expressions in the term but will not
// recursively descend into child terms.
func (t Term) shallowVisitExpressions(f func(hcl.Expression)) {
	if t.expr != nil {
		f(*t.expr)
	} else {
		for _, attr := range t.attrs {
			f(attr)
		}
		if t.count != nil {
			f(*t.count)
		}
		if t.forEach != nil {
			f(*t.forEach)
		}
	}
}

// VisitExpressions recursively visits all expressions in a tree of terms.
func (t Term) VisitExpressions(f func(hcl.Expression)) {
	t.shallowVisitExpressions(f)
	for _, blocks := range t.blocks {
		for _, block := range blocks {
			block.VisitExpressions(f)
		}
	}
}

type TermDependency struct {
	Range     *hcl.Range // Optional range
	Traversal hcl.Traversal
}

func (t Term) Dependencies() []TermDependency {
	// If the variable matches the iterator, it is not a real dependency
	// and we can filter it out.
	filter := func(v hcl.Traversal) bool { return false }
	if t.iterator != "" {
		filter = func(v hcl.Traversal) bool {
			return !v.IsRelative() && v.RootName() == t.iterator
		}
	}

	dependencies := []TermDependency{}
	t.shallowVisitExpressions(func(e hcl.Expression) {
		for _, variable := range e.Variables() {
			if !filter(variable) {
				loc := e.Range()
				dependencies = append(dependencies, TermDependency{
					Range:     &loc,
					Traversal: variable,
				})
			}
		}
	})

	for _, blocks := range t.blocks {
		for _, block := range blocks {
			for _, variable := range block.Dependencies() {
				if !filter(variable.Traversal) {
					dependencies = append(dependencies, variable)
				}
			}
		}
	}

	return dependencies
}

func (t Term) evaluateExpr(
	evalExpr func(expr hcl.Expression, extraVars cty.Value) (cty.Value, hcl.Diagnostics),
) (cty.Value, hcl.Diagnostics) {
	if t.expr != nil {
		return evalExpr(*t.expr, cty.EmptyObjectVal)
	} else {
		obj := map[string]cty.Value{}
		diagnostics := hcl.Diagnostics{}

		for k, attr := range t.attrs {
			val, diags := evalExpr(attr, cty.EmptyObjectVal)
			diagnostics = append(diagnostics, diags...)
			obj[k] = val
		}

		blists := map[string][]cty.Value{}
		for k, blocks := range t.blocks {
			blists[k] = []cty.Value{}
			for _, block := range blocks {
				val, diags := block.Evaluate(evalExpr)
				diagnostics = append(diagnostics, diags...)
				// If we are dealing with a block that has a forEach on it, we
				// allow it to return multiple elements.
				if block.forEach != nil && val.IsKnown() && !val.IsNull() && val.CanIterateElements() {
					blists[k] = append(blists[k], val.AsValueSlice()...)
				} else {
					blists[k] = append(blists[k], val)
				}
			}
		}
		for k, blocks := range blists {
			obj[k] = cty.TupleVal(blocks)
		}

		return cty.ObjectVal(obj), diagnostics
	}
}

type foreachAccumulator interface {
	add(key string, val cty.Value)
	val() cty.Value
}

type foreachArrayAccumulator struct {
	array []cty.Value
}

func (acc *foreachArrayAccumulator) add(key string, val cty.Value) {
	acc.array = append(acc.array, val)
}

func (acc *foreachArrayAccumulator) val() cty.Value {
	return cty.TupleVal(acc.array)
}

type foreachObjectAccumulator struct {
	object map[string]cty.Value
}

func (acc *foreachObjectAccumulator) add(key string, val cty.Value) {
	acc.object[key] = val
}

func (acc *foreachObjectAccumulator) val() cty.Value {
	return cty.ObjectVal(acc.object)
}

func (t Term) Evaluate(
	evalExpr func(expr hcl.Expression, extraVars cty.Value) (cty.Value, hcl.Diagnostics),
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
		countVal, diags := evalExpr(*t.count, cty.EmptyObjectVal)
		diagnostics = append(diagnostics, diags...)
		if count := parseCount(countVal); count != nil {
			arr := []cty.Value{}
			for i := int64(0); i < *count; i++ {
				val, diags := t.evaluateExpr(func(e hcl.Expression, v cty.Value) (cty.Value, hcl.Diagnostics) {
					v = MergeVal(v, NestVal(LocalName{"count", "index"}, cty.NumberIntVal(i)))
					return evalExpr(e, v)
				})
				diagnostics = append(diagnostics, diags...)
				arr = append(arr, val)
			}
			return cty.TupleVal(arr), diagnostics
		}
	}

	if t.forEach != nil {
		diagnostics := hcl.Diagnostics{}
		forEachVal, diags := evalExpr(*t.forEach, cty.EmptyObjectVal)
		diagnostics = append(diagnostics, diags...)

		evalWithEach := func(each cty.Value) cty.Value {
			val, diags := t.evaluateExpr(func(e hcl.Expression, v cty.Value) (cty.Value, hcl.Diagnostics) {
				v = MergeVal(v, NestVal(LocalName{t.iterator}, each))
				return evalExpr(e, v)
			})
			diagnostics = append(diagnostics, diags...)
			return val
		}

		if !forEachVal.IsNull() && forEachVal.IsKnown() {
			if forEachVal.Type().IsMapType() || forEachVal.Type().IsObjectType() {
				object := map[string]cty.Value{}
				for k, v := range forEachVal.AsValueMap() {
					object[k] = evalWithEach(cty.ObjectVal(map[string]cty.Value{
						"key":   cty.StringVal(k),
						"value": v,
					}))
				}
				return cty.ObjectVal(object), diagnostics
			} else if forEachVal.Type().IsSetType() {
    			// Building an object is preferred since, but fall back to
    			// building a tuple if we have a key that's not a string.
				object := map[string]cty.Value{}
				tuple := []cty.Value{}
				for _, v := range forEachVal.AsValueSet().Values() {
					val := evalWithEach(cty.ObjectVal(map[string]cty.Value{
						"key":   v,
						"value": v,
					}))
    				if object != nil && v.Type() == cty.String {
        				object[v.AsString()] = val
        				tuple = append(tuple, val)
    				} else {
        				object = nil
						tuple = append(tuple, val)
    				}
				}
				if object != nil {
    				return cty.ObjectVal(object), diagnostics
				}
				return cty.TupleVal(tuple), diagnostics
			} else if forEachVal.Type().IsTupleType() || forEachVal.Type().IsListType() {
				tuple := []cty.Value{}
				for _, v := range forEachVal.AsValueSlice() {
					val := evalWithEach(cty.ObjectVal(map[string]cty.Value{
						"value": v,
					}))
					tuple = append(tuple, val)
				}
				return cty.TupleVal(tuple), diagnostics
			}

			return cty.TupleVal([]cty.Value{}), diagnostics
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
		head := name[0]
		if t.children == nil {
			t.children = map[string]*termLocalTree{}
		}
		if _, ok := t.children[head]; !ok {
			t.children[head] = &termLocalTree{}
		}
		t.children[head].addTerm(name[1:], term)
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
		head := name[0]
		if child, ok := t.children[head]; ok {
			prefix, term := child.lookupByPrefix(name[1:])
			if term != nil {
				prefix = append(LocalName{head}, prefix...)
				return prefix, term
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
			child.visitTerms(name.Add(key), f)
		}
	}
}
