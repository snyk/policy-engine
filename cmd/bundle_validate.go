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
