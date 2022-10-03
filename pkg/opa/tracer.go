package opa

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/open-policy-agent/opa/topdown"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/ast/location"
)

type DummyExecutionTracer struct {
	pathSet *pathSet
}

func NewDummyExecutionTracer() *DummyExecutionTracer {
	return &DummyExecutionTracer{
		pathSet: newPathSet(),
	}
}

func (t *DummyExecutionTracer) term(term *ast.Term) {
	if term != nil && term.IsGround() {
		if term.Location != nil {
			if encoded := t.decodePath(term.Location.File); encoded != nil {
				t.pathSet.Add(encoded)
			}
		}
	}
}

func (t *DummyExecutionTracer) Config() topdown.TraceConfig {
	return topdown.TraceConfig{
		PlugLocalVars: false,
	}
}

func (t *DummyExecutionTracer) Enabled() bool {
	return true
}

func (t *DummyExecutionTracer) TraceEvent(event topdown.Event) {
	if event.Op == topdown.UnifyOp {
		if expr, ok := event.Node.(*ast.Expr); ok {
			if terms, ok := expr.Terms.([]*ast.Term); ok && len(terms) == 3 {
				fmt.Fprintf(os.Stderr, "TraceUnify: %s = %s\n", terms[1].String(), terms[2].String())
				t.term(event.Plug(terms[1]))
				t.term(event.Plug(terms[2]))
			}
		}
	}
	if event.Op == topdown.EvalOp {
		if expr, ok := event.Node.(*ast.Expr); ok {
			if terms, ok := expr.Terms.([]*ast.Term); ok && len(terms) > 0 {
				if expr.IsEquality() {
					lhs := event.Plug(terms[1])
					rhs := event.Plug(terms[2])
					fmt.Fprintf(os.Stderr, "TraceEquality: %s = %s\n", lhs.String(), rhs.String())
				}

				if ref, ok := terms[0].Value.(ast.Ref); ok {
					if _, ok := ast.BuiltinMap[ref.String()]; ok {
						operands := make([]*ast.Term, len(terms)-1)
						for i, term := range terms[1:] {
							operands[i] = event.Plug(term)
						}

						strs := make([]string, len(operands))
						for i, term := range operands {
							strs[i] = fmt.Sprintf(term.String())
						}

						fmt.Fprintf(os.Stderr, "TraceEval: %s(%s)\n", terms[0].String(), strings.Join(strs, ", "))
						for _, term := range operands {
							t.term(term)
						}
					}
				}
			}
		}
	}
}

func (t *DummyExecutionTracer) DecorateValue(top ast.Value) error {
	path := []interface{}{}
	var decorateValue func(ast.Value) error
	var decorateTerm func(*ast.Term) error
	decorateTerm = func(term *ast.Term) error {
		encoded, err := t.encodePath(path)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Decorated with %s\n", encoded)
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

func (t *DummyExecutionTracer) Flush() [][]interface{} {
    list := t.pathSet.List()
    t.pathSet = newPathSet()
	return list
}

func (t *DummyExecutionTracer) encodePath(path []interface{}) (string, error) {
	bytes, err := json.Marshal(path)
	if err != nil {
		return "", err
	}
	return "path:" + string(bytes), nil
}

func (t *DummyExecutionTracer) decodePath(encoded string) []interface{} {
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

type pathSet struct {
	intKeys    map[int]*pathSet
	stringKeys map[string]*pathSet
}

func newPathSet() *pathSet {
	return &pathSet{
		intKeys:    map[int]*pathSet{},
		stringKeys: map[string]*pathSet{},
	}
}

func (ps *pathSet) addInt(k int, path []interface{}) {
	if _, ok := ps.intKeys[k]; !ok {
		ps.intKeys[k] = newPathSet()
	}
	ps.intKeys[k].Add(path)
}

func (ps *pathSet) addString(k string, path []interface{}) {
	if _, ok := ps.stringKeys[k]; !ok {
		ps.stringKeys[k] = newPathSet()
	}
	ps.stringKeys[k].Add(path)
}

func (ps *pathSet) Add(path []interface{}) {
	if len(path) <= 0 {
		return
	}
	switch k := path[0].(type) {
	case int:
		ps.addInt(k, path[1:])
	case float64:
		ps.addInt(int(k), path[1:])
	case string:
		ps.addString(k, path[1:])
	default:
		fmt.Fprintf(os.Stderr, "uncovered: %t\n", k)
	}
}

func (ps *pathSet) List() [][]interface{} {
	paths := [][]interface{}{}
	for i, child := range ps.intKeys {
		for _, childPath := range child.List() {
			path := make([]interface{}, len(childPath)+1)
			path[0] = i
			copy(path[1:], childPath)
			paths = append(paths, path)
		}
	}
	for i, child := range ps.stringKeys {
		for _, childPath := range child.List() {
			path := make([]interface{}, len(childPath)+1)
			path[0] = i
			copy(path[1:], childPath)
			paths = append(paths, path)
		}
	}
	if len(paths) <= 0 {
		paths = append(paths, []interface{}{})
	}
	return paths
}

