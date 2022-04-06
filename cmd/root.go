package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/fugue/regula/v2/pkg/rego"
	"github.com/spf13/cobra"

	"github.com/snyk/unified-policy-engine/pkg/semantics"
	"github.com/snyk/unified-policy-engine/pkg/upe"
	"github.com/snyk/unified-policy-engine/pkg/input"
)

var cmdRegoPaths []string

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "upe",
	Short: "Unified Policy Engine",
	Run: func(cmd *cobra.Command, args []string) {
		options := upe.UpeOptions{
			Providers: []rego.RegoProvider{
				rego.LocalProvider(cmdRegoPaths),
			},
			Builtins: semantics.Builtins(),
		}

		inputs, err := input.LoadRegulaInputs(args)
		check(err)

		ctx := context.Background()
		upe, err := upe.LoadUpe(ctx, options)
		check(err)

		for _, input := range inputs {
			for _, ruleName := range upe.IterateRules() {
				rule, err := semantics.DetectSemantics(upe, ctx, ruleName)
				check(err)
				report, err := rule.Run(upe, ctx, input)
				check(err)

				bytes, err := json.MarshalIndent(report, "  ", "  ")
				check(err)
				fmt.Fprintf(os.Stdout, "%s\n", string(bytes))
			}
		}
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringSliceVarP(&cmdRegoPaths, "REGO_PATH", "d", cmdRegoPaths, "Rego paths to load")
}
