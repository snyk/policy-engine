package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version string = "dev"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display version",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintf(os.Stdout, "%s\n", version)
		return nil
	},
}
