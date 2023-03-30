package regobind

import (
	"context"
	"fmt"
	"reflect"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/topdown"
)

type Options struct {
	Modules             map[string]*ast.Module
	Document            map[string]interface{}
	Capabilities        *ast.Capabilities
	StrictBuiltinErrors bool
}

func (options *Options) Add(other Options) {
	if options.Modules == nil && other.Modules != nil {
		options.Modules = other.Modules
	} else if other.Modules != nil {
		for k, mod := range other.Modules {
			options.Modules[k] = mod
		}
	}

	if options.Document == nil {
		options.Document = other.Document
	}

	if options.Capabilities == nil {
		options.Capabilities = other.Capabilities
	}
}

type State struct {
	compiler *ast.Compiler
	store    storage.Store
}

func NewState(options *Options) (*State, error) {
	compiler := ast.NewCompiler()

	if options.Capabilities != nil {
		compiler = compiler.WithCapabilities(options.Capabilities)
	}

	document := options.Document
	if document == nil {
		document = map[string]interface{}{}
	}

	compiler.Compile(options.Modules)
	if len(compiler.Errors) > 0 {
		return nil, compiler.Errors
	}
	return &State{
		compiler: compiler,
		store:    inmem.NewFromObject(document),
	}, nil
}

type Query struct {
	Query               string
	Builtins            map[string]*topdown.Builtin
	StrictBuiltinErrors bool
	Tracers             []topdown.QueryTracer
}

func (q *Query) Add(other *Query) *Query {
	if other.Query != "" {
		q.Query = other.Query
	}
	if q.Builtins == nil && other.Builtins != nil {
		q.Builtins = other.Builtins
	} else if other.Builtins != nil {
		for k, builtin := range other.Builtins {
			q.Builtins[k] = builtin
		}
	}
	q.StrictBuiltinErrors = q.StrictBuiltinErrors || other.StrictBuiltinErrors
	q.Tracers = append(q.Tracers, other.Tracers...)
	return q
}

func (s *State) Query(
	ctx context.Context,
	query *Query,
	buffer interface{},
	process func() error,
) error {
	bufferValue := reflect.ValueOf(buffer)
	bufferKind := bufferValue.Type().Kind()
	if bufferKind != reflect.Pointer {
		return fmt.Errorf("non-pointer receiver passed to Query")
	}

	parsed, err := ast.ParseBody(query.Query)
	if err != nil {
		return err
	}

	if len(parsed) > 1 {
		return fmt.Errorf("query expects a single term but got: %s", query.Query)
	}

	captureVar := ast.Var("_capture")
	err = capture(captureVar, parsed)
	if err != nil {
		return err
	}

	compiled, err := s.compiler.QueryCompiler().Compile(parsed)
	if err != nil {
		return err
	}

	q := topdown.NewQuery(compiled).
		WithCompiler(s.compiler).
		WithStore(s.store).
		WithBuiltins(query.Builtins)

	for _, tracer := range query.Tracers {
		q = q.WithQueryTracer(tracer)
	}

	return q.Iter(ctx, func(qr topdown.QueryResult) error {
		bufferValue.Elem().Set(reflect.Zero(bufferValue.Type().Elem()))

		regoValue := qr[captureVar]
		err := Bind(regoValue.Value, buffer)
		if err != nil {
			return err
		}

		return process()
	})
}

func capture(variable ast.Var, body ast.Body) error {
	if len(body) != 1 {
		return fmt.Errorf("query expects a single term but got: %s", body.String())
	}

	varTerm := &ast.Term{Value: variable}
	expr := body[0]
	switch terms := expr.Terms.(type) {
	case *ast.Term:
		expr.Terms = ast.Equality.Expr(terms, varTerm).Terms
	case []*ast.Term:
		// NOTE: we assume the call is unsaturated here.
		expr.Terms = append(terms, varTerm)
	}

	return nil
}
