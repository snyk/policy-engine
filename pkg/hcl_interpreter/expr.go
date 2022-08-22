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

// Utilities for working with expressions.
package hcl_interpreter

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// ExprAttributes tries to gather all attributes that are being used in a given
// expression.  For example, for:
//
//     aws_s3_bucket.bucket[count.index].acl
//
// It would return [acl].
func ExprAttributes(expr hcl.Expression) []LocalName {
	names := []LocalName{}
	if syn, ok := expr.(hclsyntax.Expression); ok {
		hclsyntax.VisitAll(syn, func(node hclsyntax.Node) hcl.Diagnostics {
			switch e := node.(type) {
			case *hclsyntax.RelativeTraversalExpr:
				if name, err := TraversalToLocalName(e.Traversal); err == nil {
					names = append(names, name)
				}
			case *hclsyntax.IndexExpr:
				if key := ExprToLiteralString(e.Key); key != nil {
					name := LocalName{*key}
					names = append(names, name)
				}
			}
			return nil
		})
	}
	return names
}

func ExprToLiteralString(expr hcl.Expression) *string {
	if e, ok := expr.(*hclsyntax.LiteralValueExpr); ok {
		return ValueToString(e.Val)
	}
	return nil
}
