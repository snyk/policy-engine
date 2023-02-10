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

// Look in `/pkg/hcl_interpreter/README.md` for an explanation of how this
// works.
package hcl_interpreter

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

type phantomAttrs struct {
	// A set of phantom attributes per FullName.
	attrs map[string]map[string]struct{}
}

func newPhantomAttrs() *phantomAttrs {
	return &phantomAttrs{
		attrs: map[string]map[string]struct{}{},
	}
}

func (pa *phantomAttrs) analyze(name FullName, term Term) {
	term.VisitExpressions(func(expr hcl.Expression) {
		exprAttrs := exprAttributes(expr)
		for _, traversal := range expr.Variables() {
			local, err := TraversalToLocalName(traversal)
			if err != nil {
				continue
			}

			full := FullName{Module: name.Module, Local: local}
			if asResourceName, trailing := full.AsResourceName(); asResourceName != nil {
				attrs := map[string]struct{}{}
				attrs[LocalNameToString(trailing)] = struct{}{}
				for _, attr := range exprAttrs {
					attrs[LocalNameToString(attr)] = struct{}{}
				}

				if len(attrs) > 0 {
					resourceKey := asResourceName.ToString()
					if _, ok := pa.attrs[resourceKey]; !ok {
						pa.attrs[resourceKey] = map[string]struct{}{}
					}
					for k := range attrs {
						pa.attrs[resourceKey][k] = struct{}{}
					}
				}
			}
		}
	})
}

func (pa *phantomAttrs) add(name FullName, val cty.Value) cty.Value {
	rk := name.ToString()

	var patch func(LocalName, string, cty.Value) cty.Value
	patch = func(local LocalName, ref string, val cty.Value) cty.Value {
		if !val.IsKnown() || val.IsNull() {
			return val // Avoid panicking on unknowns
		} else if val.Type().IsObjectType() {
			// Insert the literal string value at the given location.
			sparse := NestVal(local, cty.StringVal(ref))
			return MergeVal(sparse, val)
		} else if val.Type().IsTupleType() {
			// Patching counted resources.
			arr := []cty.Value{}
			for i, v := range val.AsValueSlice() {
				indexedRef := fmt.Sprintf("%s[%d]", ref, i)
				arr = append(arr, patch(local, indexedRef, v))
			}
			return cty.TupleVal(arr)
		}
		return val
	}

	if attrs, ok := pa.attrs[rk]; ok {
		for attr := range attrs {
			if full, _ := StringToFullName(attr); full != nil {
				val = patch(full.Local, name.ToString(), val)
			}
		}
	}
	return val
}

// exprAttributes tries to gather all attributes that are being used in a given
// expression.  For example, for:
//
//     aws_s3_bucket.bucket[count.index].acl
//
// It would return [acl].
func exprAttributes(expr hcl.Expression) []LocalName {
	names := []LocalName{}
	if syn, ok := expr.(hclsyntax.Expression); ok {
		hclsyntax.VisitAll(syn, func(node hclsyntax.Node) hcl.Diagnostics {
			switch e := node.(type) {
			case *hclsyntax.RelativeTraversalExpr:
				if name, err := TraversalToLocalName(e.Traversal); err == nil {
					names = append(names, name)
				}
			case *hclsyntax.IndexExpr:
				if key := exprToLiteralString(e.Key); key != nil {
					name := LocalName{*key}
					names = append(names, name)
				}
			}
			return nil
		})
	}
	return names
}

func exprToLiteralString(expr hcl.Expression) *string {
	if e, ok := expr.(*hclsyntax.LiteralValueExpr); ok {
		return ValueToString(e.Val)
	}
	return nil
}
