package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/tester"
	"github.com/snyk/policy-engine/pkg/data"
	"github.com/snyk/policy-engine/pkg/engine"
	"github.com/snyk/policy-engine/pkg/policy"
	"github.com/spf13/cobra"
)

const noTestsFoundCode = 2

var (
	cmdTestFilter string
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

		compiler := ast.NewCompiler().WithCapabilities(policy.Capabilities())
		ch, err := tester.NewRunner().
			SetCompiler(compiler).
			SetStore(store).
			SetModules(consumer.Modules).
			Filter(cmdTestFilter).
			RunTests(ctx, txn)
		if err != nil {
			return err
		}

		// exit with non-zero when no tests found
		exitCode := noTestsFoundCode
		dup := make(chan *tester.Result)
		go func() {
			defer close(dup)
			for tr := range ch {
				if tr.Pass() {
					exitCode = 0
				} else {
					exitCode = 1
				}
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

		if exitCode == noTestsFoundCode {
			fmt.Fprintln(reporter.Output, "no test cases found")
		}

		os.Exit(exitCode)
		return nil
	},
}

func init() {
	testCmd.Flags().StringVarP(&cmdTestFilter, "filter", "f", "", "Regular expression to filter tests by.")
}
