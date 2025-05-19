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

// Helper to implement rego testing.
package test

import (
	"context"
	"fmt"
	"os"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/tester"
	"github.com/snyk/policy-engine/pkg/data"
	"github.com/snyk/policy-engine/pkg/engine"
	"github.com/snyk/policy-engine/pkg/policy"
	"github.com/snyk/policy-engine/pkg/snapshot_testing"
)

type Options struct {
	Providers       []data.Provider
	UpdateSnapshots bool
	Verbose         bool
	Filter          string // Regular expression to filter tests.
}

type Result struct {
	Passed       bool
	NoTestsFound bool
}

func Test(ctx context.Context, options Options) (Result, error) {
	var result Result

	providers := []data.Provider{
		data.PureRegoBuiltinsProvider(),
		data.PureRegoLibProvider(),
	}
	providers = append(providers, options.Providers...)
	consumer := engine.NewPolicyConsumer()
	for _, provider := range providers {
		if err := provider(ctx, consumer); err != nil {
			return result, err
		}
	}

	store := inmem.New()
	txn, err := store.NewTransaction(ctx)
	if err != nil {
		return result, err
	}
	defer store.Abort(ctx, txn)

	capabilities := policy.Capabilities()
	capabilities.Builtins = append(capabilities.Builtins, snapshot_testing.MatchBuiltin)

	compiler := ast.NewCompiler().
		WithCapabilities(capabilities).
		WithEnablePrintStatements(true)

	ch, err := tester.NewRunner().
		AddCustomBuiltins([]*tester.Builtin{
			{
				Decl: snapshot_testing.MatchBuiltin,
				Func: rego.FunctionDyn(
					&rego.Function{
						Name:    snapshot_testing.MatchBuiltin.Name,
						Decl:    snapshot_testing.MatchBuiltin.Decl,
						Memoize: false,
					},
					snapshot_testing.MatchTestImpl(options.UpdateSnapshots),
				),
			},
		}).
		SetCompiler(compiler).
		EnableTracing(options.Verbose).
		SetStore(store).
		SetModules(consumer.Modules).
		Filter(options.Filter).
		RunTests(ctx, txn)
	if err != nil {
		return result, err
	}

	numTestsFound := 0
	result.Passed = true
	dup := make(chan *tester.Result)
	go func() {
		defer close(dup)
		for tr := range ch {
			numTestsFound += 1
			result.Passed = result.Passed && tr.Pass()
			dup <- tr
		}
	}()

	reporter := tester.PrettyReporter{
		Output:      os.Stdout,
		FailureLine: true,
		Verbose:     options.Verbose,
	}

	if err := reporter.Report(dup); err != nil {
		return result, err
	}

	if numTestsFound == 0 {
		result.NoTestsFound = true
		fmt.Fprintln(reporter.Output, "no test cases found")
	}
	return result, nil
}
