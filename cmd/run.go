package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/snyk/unified-policy-engine/pkg/data"
	"github.com/snyk/unified-policy-engine/pkg/loader"
	"github.com/snyk/unified-policy-engine/pkg/upe"
	"github.com/spf13/cobra"
)

var (
	runCmdRules []string
	runCmdCloud *bool
)

var runCmd = &cobra.Command{
	Use:   "run [-d <rules/metadata>...] run [-r <rule ID>...] <input> [input...]",
	Short: "Unified Policy Engine",
	Run: func(cmd *cobra.Command, args []string) {
		selectedRules := map[string]bool{}
		for _, k := range runCmdRules {
			selectedRules[k] = true
		}
		providers := []data.Provider{}
		for _, path := range rootCmdRegoPaths {
			providers = append(providers, data.LocalProvider(path))
		}
		options := &upe.EngineOptions{
			Providers: providers,
			RuleIDs:   selectedRules,
		}
		inputType := loader.Auto
		if *runCmdCloud {
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

		results, err := engine.Eval(ctx, states)
		check(err)

		bytes, err := json.MarshalIndent(results, "  ", "  ")
		check(err)
		fmt.Fprintf(os.Stdout, "%s\n", string(bytes))
	},
}

func init() {
	runCmdCloud = runCmd.PersistentFlags().Bool("cloud", false, "Causes inputs to be interpreted as runtime state from Snyk Cloud.")
	runCmd.PersistentFlags().StringSliceVarP(&runCmdRules, "rule", "r", runCmdRules, "Select specific rules")
}
