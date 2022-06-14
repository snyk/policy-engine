package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/snyk/policy-engine/pkg/data"
	"github.com/snyk/policy-engine/pkg/engine"
	"github.com/snyk/policy-engine/pkg/inputs"
	"github.com/snyk/policy-engine/pkg/loader"
	"github.com/snyk/policy-engine/pkg/metrics"
	"github.com/spf13/cobra"
)

var (
	runCmdRules []string
	runCmdCloud *bool
)

var runCmd = &cobra.Command{
	Use:   "run [-d <rules/metadata>...] [-r <rule ID>...] <input> [input...]",
	Short: "Policy Engine",
	Run: func(cmd *cobra.Command, args []string) {
		logger := cmdLogger()
		m := metrics.NewLocalMetrics(logger)
		selectedRules := map[string]bool{}
		for _, k := range runCmdRules {
			selectedRules[k] = true
		}
		providers := []data.Provider{data.PureRegoLibProvider()}
		for _, path := range rootCmdRegoPaths {
			if isTgz(path) {
				f, err := os.Open(path)
				check(err)
				providers = append(providers, data.TarGzProvider(f))
			} else {
				providers = append(providers, data.LocalProvider(path))
			}
		}
		options := &engine.EngineOptions{
			Providers: providers,
			RuleIDs:   selectedRules,
			Logger:    logger,
			Metrics:   m,
		}
		inputType := loader.Auto
		if *runCmdCloud {
			inputType = loader.StreamlinedState
		}
		configLoader := loader.LocalConfigurationLoader(loader.LoadPathsOptions{
			Paths:       args,
			InputTypes:  inputs.InputTypes{inputType},
			NoGitIgnore: false,
			IgnoreDirs:  false,
		})
		loadedConfigs, err := configLoader()
		check(err)

		states := loadedConfigs.ToStates()
		ctx := context.Background()
		eng, err := engine.NewEngine(ctx, options)
		check(err)

		results := eng.Eval(ctx, &engine.EvalOptions{
			Inputs: states,
		})

		loader.AnnotateResults(loadedConfigs, results)

		bytes, err := json.MarshalIndent(results, "  ", "  ")
		check(err)
		fmt.Fprintf(os.Stdout, "%s\n", string(bytes))
		m.Log(ctx)
	},
}

func init() {
	runCmdCloud = runCmd.PersistentFlags().Bool("cloud", false, "Causes inputs to be interpreted as runtime state from Snyk Cloud.")
	runCmd.PersistentFlags().StringSliceVarP(&runCmdRules, "rule", "r", runCmdRules, "Select specific rules")
}
