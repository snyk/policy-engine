package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/snyk/unified-policy-engine/pkg/data"
	"github.com/snyk/unified-policy-engine/pkg/loader"
	"github.com/snyk/unified-policy-engine/pkg/metrics"
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
		logger := cmdLogger()
		m := metrics.NewLocalMetrics(logger)
		selectedRules := map[string]bool{}
		for _, k := range runCmdRules {
			selectedRules[k] = true
		}
		providers := []data.Provider{}
		for _, path := range rootCmdRegoPaths {
			if isTgz(path) {
				f, err := os.Open(path)
				check(err)
				providers = append(providers, data.TarGzProvider(f))
			} else {
				providers = append(providers, data.LocalProvider(path))
			}
		}
		options := &upe.EngineOptions{
			Providers: providers,
			RuleIDs:   selectedRules,
			Logger:    logger,
			Metrics:   m,
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

		results, err := engine.Eval(ctx, &upe.EvalOptions{
			Inputs: states,
		})
		check(err)

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

func peek(r io.ReadSeeker, n int) []byte {
	buf := make([]byte, n)
	_, err := r.Read(buf)
	check(err)
	r.Seek(0, io.SeekStart)
	return buf
}

func mimeType(path string) string {
	f, err := os.Open(path)
	check(err)
	defer f.Close()
	buf := peek(f, 512)
	return http.DetectContentType(buf)
}

func isTgz(path string) bool {
	info, err := os.Stat(path)
	check(err)
	if info.IsDir() {
		return false
	}
	m := mimeType(path)
	return m == "application/x-gzip" || m == "application/gzip"
}
