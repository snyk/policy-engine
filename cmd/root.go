package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/fugue/regula/v2/pkg/rego"
	"github.com/spf13/cobra"

	"github.com/snyk/unified-policy-engine/pkg/input"
	"github.com/snyk/unified-policy-engine/pkg/semantics"
	"github.com/snyk/unified-policy-engine/pkg/upe"
)

var (
	cmdMetaPaths []string
	cmdRegoPaths []string
	cmdRules     []string
)

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
		selectedRules := map[string]struct{}{}
		for _, k := range cmdRules {
			selectedRules[k] = struct{}{}
		}

		metadata := upe.EmptyMetadata()
		for _, path := range cmdMetaPaths {
			m, err := upe.LoadMetadataDirectory(path)
			check(err)
			metadata.Merge(m)
		}

		options := upe.UpeOptions{
			Metadata: metadata,
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
			for _, ruleInfo := range upe.IterateRules(ctx) {
				if _, ok := selectedRules[ruleInfo.Name]; ok || len(selectedRules) == 0 {
					rule, err := semantics.DetectSemantics(upe, ctx, ruleInfo)
					check(err)

					report, err := rule.Run(upe, ctx, input)
					check(err)

					bytes, err := json.MarshalIndent(report, "  ", "  ")
					check(err)
					fmt.Fprintf(os.Stdout, "%s\n", string(bytes))
				}
			}
		}
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringSliceVarP(&cmdMetaPaths, "meta", "m", cmdMetaPaths, "Metadata dirs to load")
	rootCmd.PersistentFlags().StringSliceVarP(&cmdRegoPaths, "data", "d", cmdRegoPaths, "Rego paths to load")
	rootCmd.PersistentFlags().StringSliceVarP(&cmdRules, "rule", "r", cmdRules, "Select specific rules")
}
