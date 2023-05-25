// © 2023 Snyk Limited All rights reserved.
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

package rego

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/topdown"
	"github.com/snyk/policy-engine/pkg/internal/withtimeout"
)

var ErrQueryTimedOut = errors.New("query timed out")

type Options struct {
	Modules      map[string]*ast.Module
	Document     map[string]interface{}
	Capabilities *ast.Capabilities
}

type State struct {
	compiler *ast.Compiler
	store    storage.Store
}

func NewState(options Options) (*State, error) {
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

// Query options can be extended in an associative way using Add.
type Query struct {
	Query               string
	Input               ast.Value
	Builtins            map[string]*topdown.Builtin
	StrictBuiltinErrors *bool // Defaults to true for us.
	Tracers             []topdown.QueryTracer
	Timeout             time.Duration
}

func (q Query) Add(other Query) Query {
	if other.Query != "" {
		q.Query = other.Query
	}
	if other.Input != nil {
		q.Input = other.Input
	}
	if q.Builtins == nil && other.Builtins != nil {
		q.Builtins = other.Builtins
	} else if other.Builtins != nil {
		builtins := map[string]*topdown.Builtin{}
		for k, builtin := range q.Builtins {
			q.Builtins[k] = builtin
		}
		for k, builtin := range other.Builtins {
			q.Builtins[k] = builtin
		}
		q.Builtins = builtins
	}
	if other.StrictBuiltinErrors != nil {
		q.StrictBuiltinErrors = other.StrictBuiltinErrors
	}
	if len(q.Tracers) == 0 && len(other.Tracers) > 0 {
		q.Tracers = other.Tracers
	} else if len(other.Tracers) > 0 {
		tracers := []topdown.QueryTracer{}
		tracers = append(tracers, q.Tracers...)
		tracers = append(tracers, other.Tracers...)
		q.Tracers = tracers
	}
	return q
}

func (s *State) Query(
	ctx context.Context,
	query Query,
	process func(ast.Value) error,
) error {
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

	txn, err := s.store.NewTransaction(ctx)
	if err != nil {
		return err
	}
	defer s.store.Abort(ctx, txn)

	q := topdown.NewQuery(compiled).
		WithCompiler(s.compiler).
		WithStore(s.store).
		WithTransaction(txn).
		WithBuiltins(query.Builtins).
		WithStrictBuiltinErrors(query.StrictBuiltinErrors == nil || *query.StrictBuiltinErrors).
		WithInput(&ast.Term{Value: query.Input})

	for _, tracer := range query.Tracers {
		q = q.WithQueryTracer(tracer)
	}

	do := func(ctx context.Context) error {
		return q.Iter(ctx, func(qr topdown.QueryResult) error {
			regoValue := qr[captureVar]
			return process(regoValue.Value)
		})
	}

	if query.Timeout > 0 {
		return withtimeout.Do(ctx, query.Timeout, ErrQueryTimedOut, do)
	} else {
		return do(ctx)
	}
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
