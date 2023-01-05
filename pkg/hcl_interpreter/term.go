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
