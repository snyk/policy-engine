package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/snyk/unified-policy-engine/pkg/data"
	"github.com/snyk/unified-policy-engine/pkg/loader"
	"github.com/snyk/unified-policy-engine/pkg/logging"
	"github.com/snyk/unified-policy-engine/pkg/upe"
	"github.com/spf13/cobra"
)

var (
	cmdRegoPaths []string
	cmdRules     []string
	cmdCloud     *bool
)

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "unified-policy-engine [-d <rules/metadata>...] [-r <rule ID>...] <input> [input...]",
	Short: "Unified Policy Engine",
	Run: func(cmd *cobra.Command, args []string) {
		logger := logging.NewZeroLogger(zerolog.Logger{}.
			Level(zerolog.GlobalLevel()).
			Output(zerolog.ConsoleWriter{Out: os.Stderr}).
			With().Timestamp().Logger())
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
			Logger:    logger,
		}
		inputType := loader.Auto
		if *cmdCloud {
			inputType = loader.TfRuntime
		}
		configLoader := loader.LocalConfigurationLoader(loader.LoadPathsOptions{
			Paths:       args,
			InputTypes:  []loader.InputType{inputType},
			NoGitIgnore: false,
			IgnoreDirs:  false,
		})
		loadedConfigs, err := configLoader()
		check(err)

		states := loadedConfigs.ToStates()
		ctx := context.Background()
		engine, err := upe.NewEngine(ctx, options)
		check(err)

		results, err := engine.Eval(ctx, upe.EvalOptions{
			Inputs: states,
			Logger: logger,
		})
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
	cmdCloud = rootCmd.PersistentFlags().Bool("cloud", false, "Causes inputs to be interpreted as runtime state from Snyk Cloud.")
	rootCmd.PersistentFlags().StringSliceVarP(&cmdRegoPaths, "data", "d", cmdRegoPaths, "Rego paths to load")
	rootCmd.PersistentFlags().StringSliceVarP(&cmdRules, "rule", "r", cmdRules, "Select specific rules")
}
