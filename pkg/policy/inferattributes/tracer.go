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
	if term != nil && term.IsGround() {
		if term.Location != nil {
			if encoded := decodePath(term.Location.File); encoded != nil {
				t.pathSet.Add(encoded)
			}
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
	if event.Op == topdown.UnifyOp {
		if expr, ok := event.Node.(*ast.Expr); ok {
			if terms, ok := expr.Terms.([]*ast.Term); ok && len(terms) == 3 {
				t.coverTerm(event.Plug(terms[1]))
				t.coverTerm(event.Plug(terms[2]))
			}
		}
	}
	if event.Op == topdown.EvalOp {
		if expr, ok := event.Node.(*ast.Expr); ok {
			if terms, ok := expr.Terms.([]*ast.Term); ok && len(terms) > 0 {
				if ref, ok := terms[0].Value.(ast.Ref); ok {
					if _, ok := ast.BuiltinMap[ref.String()]; ok {
						for _, term := range terms[1:] {
							t.coverTerm(event.Plug(term))
						}
					}
				}
			}
		}
	}
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
func DecorateValue(prefix []interface{}, top ast.Value) error {
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
	return decorateValue(top)
}
