// Copyright 2022 Snyk Ltd
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
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/format"
	"github.com/snyk/policy-engine/pkg/input"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

var (
	cmdFixturePackage string
)

var fixtureCmd = &cobra.Command{
	Use:   "fixture",
	Short: "Generate test fixture",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("Expected a single input but got %d", len(args))
		}
		detector, err := input.DetectorByInputTypes(input.Types{
			input.Auto,
			input.StreamlinedState,
		})
		if err != nil {
			return err
		}
		i, err := input.NewDetectable(afero.OsFs{}, args[0])
		if err != nil {
			return err
		}
		loader := input.NewLoader(detector)
		loaded, err := loader.Load(i, input.DetectOptions{})
		if err != nil {
			return err
		}
		if !loaded {
			return fmt.Errorf("Unable to find recognized input in %s", args[0])
		}
		packageName := cmdFixturePackage
		if packageName == "" {
			normalized := filepath.ToSlash(args[0])
			normalized = strings.TrimSuffix(normalized, filepath.Ext(normalized))
			normalized = strings.ReplaceAll(normalized, "-", "_")
			parts := []string{}
			for _, part := range strings.Split(normalized, "/") {
				if part != "" {
					parts = append(parts, part)
				}
			}
			packageName = strings.Join(parts, ".")
		}

		states := loader.ToStates()
		if len(states) != 1 {
			return fmt.Errorf("Expected a single state but got %d", len(states))
		}
		bytes, err := json.MarshalIndent(states[0], "", "  ")
		if err != nil {
			return err
		}
		bytes = []byte(fmt.Sprintf(`package %s
mock_input = %s`, packageName, string(bytes)))

		bytes, err = format.Source("-", bytes)
		if err != nil {
			return err
		}

		fmt.Printf("%s", string(bytes))
		return nil
	},
}

func init() {
	fixtureCmd.PersistentFlags().StringVar(&cmdFixturePackage, "package", "", "Explicitly set package name")
}
