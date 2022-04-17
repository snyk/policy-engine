package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cmdRegoPaths []string
	cmdRules     []string
)

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "upe",
	Short: "Unified Policy Engine",
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringSliceVarP(&cmdRegoPaths, "data", "d", cmdRegoPaths, "Rego paths to load")
	rootCmd.PersistentFlags().StringSliceVarP(&cmdRules, "rule", "r", cmdRules, "Select specific rules")
}
