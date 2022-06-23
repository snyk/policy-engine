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
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

var (
	runCmdRules []string
)

var runCmd = &cobra.Command{
	Use:   "run [-d <rules/metadata>...] [-r <rule ID>...] <input> [input...]",
	Short: "Policy Engine",
	RunE: func(cmd *cobra.Command, args []string) error {
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
			loaded, err := loader.Load(detectable, input.DetectOptions{})
			if err != nil {
				return err
			}
			if loaded {
				continue
			}
			if dir, ok := detectable.(*input.Directory); ok {
				walkFunc := func(d input.Detectable, depth int) (bool, error) {
					return loader.Load(d, input.DetectOptions{})
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
			Inputs: states,
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
	runCmd.PersistentFlags().StringSliceVarP(&runCmdRules, "rule", "r", runCmdRules, "Select specific rules")
}
