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
	"context"
	"os"

	"github.com/spf13/cobra"

	"github.com/snyk/policy-engine/pkg/rego/test"
)

const noTestsFoundCode = 2

var (
	cmdTestFilter          string
	cmdTestUpdateSnapshots bool
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Run OPA tests",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		result, err := test.Test(ctx, test.Options{
			Providers:       rootCmdRegoProviders(),
			UpdateSnapshots: cmdTestUpdateSnapshots,
			Filter:          cmdTestFilter,
			Verbose:         rootCmdVerbosity.Debug(),
		})
		if err != nil {
			return err
		}

		if result.NoTestsFound {
			// exit with non-zero when no tests found
			os.Exit(noTestsFoundCode)
		}

		if result.NoTestsFound {
			os.Exit(noTestsFoundCode)
		} else if result.Passed {
			os.Exit(0)
		} else {
			os.Exit(1)
		}

		return nil
	},
}

func init() {
	testCmd.Flags().StringVarP(&cmdTestFilter, "filter", "f", "", "Regular expression to filter tests by.")
	testCmd.Flags().BoolVar(&cmdTestUpdateSnapshots, "update-snapshots", false, "Updates snapshots used in snapshot_testing.match")
}
