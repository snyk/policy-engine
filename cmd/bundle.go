package cmd

import "github.com/spf13/cobra"

var bundleCmd = &cobra.Command{
	Use: "bundle",
}

func init() {
	bundleCmd.AddCommand(bundleCreateCmd)
	bundleCmd.AddCommand(bundleValidateCmd)
	bundleCmd.AddCommand(bundleShowCmd)
	rootCmd.AddCommand(bundleCmd)
}
