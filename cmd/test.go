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
		for _, path := range rootCmdRegoPaths {
			providers = append(providers, data.LocalProvider(path))
		}

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

		compiler := ast.NewCompiler().WithCapabilities(capabilities)
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
			CapturePrintOutput(true).
			EnableTracing(*rootCmdVerbose).
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
			Verbose:     true,
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
