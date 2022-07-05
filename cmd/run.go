package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/snyk/policy-engine/pkg/data"
	"github.com/snyk/policy-engine/pkg/engine"
	"github.com/snyk/policy-engine/pkg/input"
	"github.com/snyk/policy-engine/pkg/metrics"
	"github.com/snyk/policy-engine/pkg/snapshot_testing"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

var (
	runCmdRules   []string
	runVarFiles   []string
	runCmdWorkers *int
)

var runCmd = &cobra.Command{
	Use:   "run [-d <rules/metadata>...] [-r <rule ID>...] <input> [input...]",
	Short: "Policy Engine",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := cmdLogger()
		snapshot_testing.GlobalRegisterNoop()
		m := metrics.NewLocalMetrics(logger)
		selectedRules := map[string]bool{}
		for _, k := range runCmdRules {
			selectedRules[k] = true
		}
		providers := []data.Provider{
			data.PureRegoLibProvider(),
		}
		for _, path := range rootCmdRegoPaths {
			if isTgz(path) {
				f, err := os.Open(path)
				if err != nil {
					return err
				}
				providers = append(providers, data.TarGzProvider(f))
			} else {
				providers = append(providers, data.LocalProvider(path))
			}
		}
		detector, err := input.DetectorByInputTypes(
			input.Types{input.Auto},
		)
		if err != nil {
			return err
		}
		loader := input.NewLoader(detector)
		fsys := afero.OsFs{}
		for _, p := range args {
			detectable, err := input.NewDetectable(fsys, p)
			if err != nil {
				return err
			}
			loaded, err := loader.Load(detectable, input.DetectOptions{
				VarFiles: runVarFiles,
			})
			if err != nil {
				return err
			}
			if loaded {
				continue
			}
			if dir, ok := detectable.(*input.Directory); ok {
				walkFunc := func(d input.Detectable, depth int) (bool, error) {
					return loader.Load(d, input.DetectOptions{
						VarFiles: runVarFiles,
					})
				}
				if err := dir.Walk(walkFunc); err != nil {
					return err
				}
			}
		}
		states := loader.ToStates()
		ctx := context.Background()
		eng, err := engine.NewEngine(ctx, &engine.EngineOptions{
			Providers: providers,
			RuleIDs:   selectedRules,
			Logger:    logger,
			Metrics:   m,
		})
		if err != nil {
			return err
		}
		results := eng.Eval(ctx, &engine.EvalOptions{
			Inputs:  states,
			Workers: *runCmdWorkers,
		})
		input.AnnotateResults(loader, results)

		bytes, err := json.MarshalIndent(results, "  ", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "%s\n", string(bytes))
		m.Log(ctx)
		return nil
	},
}

func init() {
	runCmdWorkers = runCmd.PersistentFlags().IntP("workers", "w", 0, "Number of workers. When 0 (the default) will use num CPUs + 1.")
	runCmd.PersistentFlags().StringSliceVarP(&runCmdRules, "rule", "r", runCmdRules, "Select specific rules")
	runCmd.PersistentFlags().StringSliceVar(&runVarFiles, "var-file", runVarFiles, "Pass in variable files")
}
