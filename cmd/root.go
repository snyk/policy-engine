package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/snyk/unified-policy-engine/pkg/data"
	"github.com/snyk/unified-policy-engine/pkg/loader"
	"github.com/snyk/unified-policy-engine/pkg/upe"
)

var (
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
		selectedRules := map[string]bool{}
		for _, k := range cmdRules {
			selectedRules[k] = true
		}

		providers := []data.Provider{}
		for _, path := range cmdRegoPaths {
			providers = append(providers, data.LocalProvider(path))
		}

		options := &upe.EngineOptions{
			Providers: providers,
			RuleIDs:   selectedRules,
		}

		configLoader := loader.LocalConfigurationLoader(loader.LoadPathsOptions{
			Paths:       args,
			InputTypes:  []loader.InputType{loader.Auto},
			NoGitIgnore: false,
			IgnoreDirs:  false,
		})
		loadedConfigs, err := configLoader()
		check(err)

		states := loadedConfigs.ToStates()
		ctx := context.Background()
		engine, err := upe.NewEngine(ctx, options)
		// upe, err := upe.LoadUpe(ctx, options)
		check(err)

		results, err := engine.Eval(ctx, states)
		check(err)

		bytes, err := json.MarshalIndent(results, "  ", "  ")
		check(err)
		fmt.Fprintf(os.Stdout, "%s\n", string(bytes))
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringSliceVarP(&cmdRegoPaths, "data", "d", cmdRegoPaths, "Rego paths to load")
	rootCmd.PersistentFlags().StringSliceVarP(&cmdRules, "rule", "r", cmdRules, "Select specific rules")
}
