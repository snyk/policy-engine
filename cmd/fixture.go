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
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/format"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	"github.com/snyk/policy-engine/pkg/input"
	"github.com/snyk/policy-engine/pkg/logging"
	"github.com/snyk/policy-engine/pkg/models"
)

var (
	cmdFixturePackage string
)

var fixtureCmd = &cobra.Command{
	Use:   "fixture",
	Short: "Generate test fixture",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := cmdLogger()
		ctx := context.Background()
		if len(args) != 1 {
			return fmt.Errorf("Expected a single input but got %d", len(args))
		}
		inputState, err := loadSingleInput(ctx, logger, args[0])
		if err != nil {
			return err
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

		bytes, err := json.MarshalIndent(inputState, "", "  ")
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

func loadSingleInput(ctx context.Context, logger logging.Logger, path string) (*models.State, error) {
	detector, err := input.DetectorByInputTypes(input.Types{input.Auto})
	if err != nil {
		return nil, err
	}
	i, err := input.NewDetectable(afero.OsFs{}, path)
	if err != nil {
		return nil, err
	}
	loader := input.NewLoader(detector)
	loaded, err := loader.Load(i, input.DetectOptions{})

	// Log non-fatal errors if we're debugging.
	if *rootCmdVerbose {
		for path, errs := range loader.Errors() {
			for _, err := range errs {
				logger.Warn(ctx, fmt.Sprintf("%s: %s", path, err))
			}
		}
	}

	if err != nil {
		return nil, err
	}
	if !loaded {
		return nil, fmt.Errorf("Unable to find recognized input in %s", path)
	}
	states := loader.ToStates()
	if len(states) != 1 {
		return nil, fmt.Errorf("Expected a single state but got %d", len(states))
	}
	return &states[0], nil
}

func init() {
	fixtureCmd.PersistentFlags().StringVar(&cmdFixturePackage, "package", "", "Explicitly set package name")
}
