// © 2023 Snyk Limited All rights reserved.
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
	"fmt"

	"github.com/snyk/policy-engine/pkg/bundle"
	"github.com/spf13/cobra"
)

var bundleValidateCmd = &cobra.Command{
	Use:   "validate <bundle> [bundle...]",
	Short: "Validate one or more bundles",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		logger := cmdLogger()
		if len(args) < 1 {
			return fmt.Errorf("at least one bundle must be specified")
		}
		bundleReaders, err := bundleReadersFromPaths(args)
		if err != nil {
			return err
		}
		allValid := true
		for _, r := range bundleReaders {
			b, err := bundle.ReadBundle(r)
			if err != nil {
				logger.WithError(err).Error(ctx, "bundle is invalid")
				allValid = false
				continue
			}
			logger.
				WithField("bundle_source_info", b.SourceInfo()).
				Info(ctx, "bundle is valid")
		}
		if allValid {
			logger.Info(ctx, "all bundles valid")
			return nil
		} else {
			cmd.SilenceUsage = true
			return fmt.Errorf("one or more bundles were invalid")
		}
	},
}
