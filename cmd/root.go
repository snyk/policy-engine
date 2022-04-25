package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var (
	rootCmdRegoPaths []string
)

var rootCmd = &cobra.Command{
	Use:   "upe",
	Short: "Unified Policy Engine",
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringSliceVarP(&rootCmdRegoPaths, "data", "d", rootCmdRegoPaths, "Rego paths to load")
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(fixtureCmd)
}
