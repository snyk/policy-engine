// Copyright 2022-2023 Snyk Ltd
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

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/tester"
	"github.com/snyk/policy-engine/pkg/data"
	"github.com/snyk/policy-engine/pkg/engine"
	"github.com/snyk/policy-engine/pkg/policy"
	"github.com/snyk/policy-engine/pkg/snapshot_testing"
	"github.com/spf13/cobra"
)

const noTestsFoundCode = 2

var (
	cmdTestFilter          string
	cmdTestUpdateSnapshots bool
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Run OPA tests",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		providers := []data.Provider{
			data.PureRegoBuiltinsProvider(),
			data.PureRegoLibProvider(),
		}
		providers = append(providers, rootCmdRegoProviders()...)

		consumer := engine.NewPolicyConsumer()
		for _, provider := range providers {
			if err := provider(ctx, consumer); err != nil {
				return err
			}
		}

		store := inmem.New()
		txn, err := store.NewTransaction(ctx)
		if err != nil {
			return err
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
						snapshot_testing.MatchTestImpl(cmdTestUpdateSnapshots),
					),
				},
			}).
			SetCompiler(compiler).
			EnableTracing(rootCmdVerbosity.Debug()).
			SetStore(store).
			SetModules(consumer.Modules).
			Filter(cmdTestFilter).
			RunTests(ctx, txn)
		if err != nil {
			return err
		}

		numTestsFound := 0
		passing := true
		dup := make(chan *tester.Result)
		go func() {
			defer close(dup)
			for tr := range ch {
				numTestsFound += 1
				passing = passing && tr.Pass()
				dup <- tr
			}
		}()

		reporter := tester.PrettyReporter{
			Output:      os.Stdout,
			FailureLine: true,
			Verbose:     rootCmdVerbosity.Debug(),
		}

		if err := reporter.Report(dup); err != nil {
			return err
		}

		if numTestsFound == 0 {
			// exit with non-zero when no tests found
			fmt.Fprintln(reporter.Output, "no test cases found")
			os.Exit(noTestsFoundCode)
		} else if passing {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	testCmd.Flags().StringVarP(&cmdTestFilter, "filter", "f", "", "Regular expression to filter tests by.")
	testCmd.Flags().BoolVar(&cmdTestUpdateSnapshots, "update-snapshots", false, "Updates snapshots used in snapshot_testing.match")
}
