// © 2022-2023 Snyk Limited All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/snyk/policy-engine/pkg/engine"
	"github.com/snyk/policy-engine/pkg/input"
	"github.com/snyk/policy-engine/pkg/metrics"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/postprocess"
	"github.com/snyk/policy-engine/pkg/snapshot_testing"
	"github.com/spf13/afero"
	"github.com/spf13/afero/tarfs"
	"github.com/spf13/cobra"
)

var runFlags struct {
	Rules    []string
	Bundles  []string
	VarFiles []string
	States   []string
	Workers  int
	Cloud    cloudOptions
}

var runCmd = &cobra.Command{
	Use:   "run [-d <rules/metadata>...] [-b <bundle>] [-r <rule ID>...] [<input> [input...]] [-s <state JSON file>]",
	Short: "Policy Engine",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := cmdLogger()
		snapshot_testing.GlobalRegisterNoop()
		m := metrics.NewLocalMetrics(logger)
		ctx := context.Background()
		bundleReaders, err := bundleReadersFromPaths(runFlags.Bundles)
		if err != nil {
			return err
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
			var detectable input.Detectable
			if isTgz(p) {
				f, err := fsys.Open(p)
				if err != nil {
					return err
				}
				gzf, err := gzip.NewReader(f)
				if err != nil {
					return err
				}
				fsys := tarfs.New(tar.NewReader(gzf))
				detectable = &input.Directory{
					Path: ".",
					Fs:   fsys,
				}
			} else {
				var err error
				detectable, err = input.NewDetectable(fsys, p)
				if err != nil {
					return err
				}
			}
			loaded, err := loader.Load(detectable, input.DetectOptions{
				VarFiles: runFlags.VarFiles,
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
						VarFiles: runFlags.VarFiles,
					})
				}
				if err := dir.Walk(walkFunc); err != nil {
					return err
				}
			}
		}

		for path, errs := range loader.Errors() {
			for _, err := range errs {
				logger.Warn(ctx, fmt.Sprintf("%s: %s", path, err))
			}
		}
		states := loader.ToStates()
		for _, path := range runFlags.States {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			raw, err := io.ReadAll(f)
			if err != nil {
				return err
			}
			state := models.State{}
			if err := json.Unmarshal(raw, &state); err != nil {
				return err
			}
			states = append(states, state)
		}
		if runFlags.Cloud.enabled() {
			cloudState, err := getCloudStates(ctx, runFlags.Cloud)
			if err != nil {
				return err
			}
			states = append(states, *cloudState)
		}
		eng := engine.NewEngine(ctx, &engine.EngineOptions{
			Providers:     rootCmdRegoProviders(),
			BundleReaders: bundleReaders,
			Logger:        logger,
			Metrics:       m,
		})
		results := eng.Eval(ctx, &engine.EvalOptions{
			Inputs:  states,
			Workers: runFlags.Workers,
			RuleIDs: runFlags.Rules,
		})
		postprocess.AddSourceLocs(results, loader)

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
	runCmd.PersistentFlags().IntVarP(&runFlags.Workers, "workers", "w", 0, "Number of workers. When 0 (the default) will use num CPUs + 1.")
	runCmd.PersistentFlags().StringSliceVarP(&runFlags.Rules, "rule", "r", runFlags.Rules, "Select specific rules")
	runCmd.PersistentFlags().StringSliceVarP(&runFlags.Bundles, "bundle", "b", runFlags.Bundles, "Select specific bundles")
	runCmd.PersistentFlags().StringSliceVar(&runFlags.VarFiles, "var-file", runFlags.VarFiles, "Pass in variable files")
	runCmd.PersistentFlags().StringSliceVarP(&runFlags.States, "state", "s", runFlags.States, "Pass in state JSON files")
	runFlags.Cloud.addFlags(runCmd)
}
