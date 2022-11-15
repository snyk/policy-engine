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

package inferattributes

import (
	"encoding/json"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/ast/location"
	"github.com/open-policy-agent/opa/topdown"
)

type Tracer struct {
	pathSet *pathSet
}

func NewTracer() *Tracer {
	return &Tracer{
		pathSet: newPathSet(),
	}
}

// coverTerm checks if a Term was decorated using DecorateValue, and if so,
// adds it to the pathSet of accessed attributes.
func (t *Tracer) coverTerm(term *ast.Term) {
	if term == nil {
		return
	}
	if encoded := extractPath(term); encoded != nil {
		t.pathSet.Add(encoded)
	} else if ref, ok := term.Value.(ast.Ref); ok {
		var encoded []interface{}
		var lastEncodedIdx int
		// Loop through elements of the ref to find the last instance of an
		// encoded path
		for idx, ele := range ref {
			if p := extractPath(ele); p != nil {
				encoded = p
				lastEncodedIdx = idx
			} else {
				break
			}
		}
		if encoded != nil {
			// If we found an encoded path in the ref, then we'll attempt to
			// build out the rest of the path that the rule was trying to
			// access.
		refLoop:
			for _, ele := range ref[lastEncodedIdx+1:] {
				if !ele.IsGround() {
					break
				}
				if v, err := ast.JSON(ele.Value); err == nil {
					switch v.(type) {
					case string, int:
						encoded = append(encoded, v)
					default:
						break refLoop
					}
				} else {
					break
				}
			}
			t.pathSet.Add(encoded)
		}
	}
}

func (t *Tracer) Config() topdown.TraceConfig {
	return topdown.TraceConfig{
		PlugLocalVars: false,
	}
}

func (t *Tracer) Enabled() bool {
	return true
}

func (t *Tracer) TraceEvent(event topdown.Event) {
	switch event.Op {
	case topdown.UnifyOp:
		t.traceUnify(event)
	case topdown.EvalOp:
		t.traceEval(event)
	}
}

func (t *Tracer) traceUnify(event topdown.Event) {
	if expr, ok := event.Node.(*ast.Expr); ok {
		operands := expr.Operands()
		if len(operands) == 2 {
			t.coverTerm(event.Plug(operands[0]))
			t.coverTerm(event.Plug(operands[1]))
		}
	}
}

func (t *Tracer) traceEval(event topdown.Event) {
	if expr, ok := event.Node.(*ast.Expr); ok {
		switch terms := expr.Terms.(type) {
		case []*ast.Term:
			if len(terms) < 1 {
				break
			}
			operator := terms[0]
			if _, ok := ast.BuiltinMap[operator.String()]; ok {
				for _, term := range terms[1:] {
					t.coverTerm(event.Plug(term))
				}
			}
		case *ast.Term:
			t.coverTerm(event.Plug(terms))
		}
	}
}

func extractPath(term *ast.Term) []interface{} {
	if term.Location != nil {
		if encoded := decodePath(term.Location.File); encoded != nil {
			return encoded
		}
	}
	return nil
}

func encodePath(path []interface{}) (string, error) {
	bytes, err := json.Marshal(path)
	if err != nil {
		return "", err
	}
	return "path:" + string(bytes), nil
}

func decodePath(encoded string) []interface{} {
	if !strings.HasPrefix(encoded, "path:") {
		return nil
	}
	encoded = strings.TrimPrefix(encoded, "path:")
	var path []interface{}
	if err := json.Unmarshal([]byte(encoded), &path); err != nil {
		return nil
	}
	return path
}

// DecorateValue stores meta-information about where the values originated
// from inside the Location attribute of the corresponding terms.  This will
// allow us to deduce which terms were used in coverTerm.
func DecorateTerm(prefix []interface{}, top *ast.Term) error {
	path := make([]interface{}, len(prefix))
	copy(path, prefix)
	var decorateValue func(ast.Value) error
	var decorateTerm func(*ast.Term) error
	decorateTerm = func(term *ast.Term) error {
		encoded, err := encodePath(path)
		if err != nil {
			return err
		}
		term.Location = &location.Location{File: encoded}
		return decorateValue(term.Value)
	}
	decorateValue = func(value ast.Value) error {
		switch value := value.(type) {
		case *ast.Array:
			for i := 0; i < value.Len(); i++ {
				path = append(path, i)
				if err := decorateTerm(value.Elem(i)); err != nil {
					return err
				}
				path = path[:len(path)-1]
			}
		case ast.Object:
			for _, key := range value.Keys() {
				if str, ok := key.Value.(ast.String); ok {
					path = append(path, str)
					if err := decorateTerm(value.Get(key)); err != nil {
						return err
					}
					path = path[:len(path)-1]
				}
			}
		}
		return nil
	}
	return decorateTerm(top)
}
