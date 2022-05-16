package cmd

import (
	"context"
	"os"

	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/tester"
	"github.com/snyk/unified-policy-engine/pkg/data"
	"github.com/snyk/unified-policy-engine/pkg/upe"
	"github.com/spf13/cobra"
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Run OPA tests",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		providers := []data.Provider{data.PureRegoProvider()}
		for _, path := range rootCmdRegoPaths {
			providers = append(providers, data.LocalProvider(path))
		}

		consumer := upe.NewPolicyConsumer()
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

		ch, err := tester.NewRunner().
			SetStore(store).
			SetModules(consumer.Modules).
			EnableTracing(true).
			RunTests(ctx, txn)
		if err != nil {
			return err
		}

		exitCode := 0
		dup := make(chan *tester.Result)
		go func() {
			defer close(dup)
			for tr := range ch {
				if !tr.Pass() {
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

		os.Exit(exitCode)
		return nil
	},
}
