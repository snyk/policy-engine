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

var cloudCommand = &cobra.Command{
	Use:   "cloud <input> [input...]",
	Short: "Evaluate cloud state files",
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
			InputTypes:  []loader.InputType{loader.TfRuntime},
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

func init() {
	rootCmd.AddCommand(cloudCommand)
}
