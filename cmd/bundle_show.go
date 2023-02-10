package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/snyk/policy-engine/pkg/bundle"
	"github.com/spf13/cobra"
)

var bundleShowCmd = &cobra.Command{
	Use:   "show <bundle> [bundle...]",
	Short: "Show the manifest and source info for one or more bundles",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("at least one bundle must be specified")
		}
		bundleReaders, err := bundleReadersFromPaths(args)
		if err != nil {
			return err
		}
		for _, r := range bundleReaders {
			b, err := bundle.ReadBundle(r)
			if err != nil {
				return err
			}
			output := map[string]interface{}{
				"manifest":    b.Manifest(),
				"source_info": b.SourceInfo(),
			}
			raw, err := json.MarshalIndent(output, "", "  ")
			if err != nil {
				return err
			}
			fmt.Printf("%s\n", raw)
		}
		return nil
	},
}
