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
	"os"

	"github.com/snyk/policy-engine/pkg/data"
	"github.com/snyk/policy-engine/pkg/engine"
	"github.com/snyk/policy-engine/pkg/snapshot_testing"
	"github.com/spf13/cobra"
)

var metadataCmd = &cobra.Command{
	Use:   "metadata [-d <rules/metadata>...]",
	Short: "Return metadata from the given rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := cmdLogger()
		snapshot_testing.GlobalRegisterNoop()
		providers := []data.Provider{
			data.PureRegoLibProvider(),
		}
		providers = append(providers, rootCmdRegoProviders()...)
		ctx := context.Background()
		eng, err := engine.NewEngine(ctx, &engine.EngineOptions{
			Providers: providers,
			Logger:    logger,
		})
		if err != nil {
			return err
		}
		metadata := eng.Metadata(ctx)
		bytes, err := json.MarshalIndent(metadata, "  ", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "%s\n", string(bytes))
		return nil
	},
}
