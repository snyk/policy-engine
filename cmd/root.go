package cmd

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/snyk/unified-policy-engine/pkg/logging"
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
	rootCmdVerbose   *bool
)

var rootCmd = &cobra.Command{
	Use:   "upe",
	Short: "Unified Policy Engine",
}

func Execute() error {
	return rootCmd.Execute()
}

func cmdLogger() logging.Logger {
	logLevel := zerolog.InfoLevel
	if *rootCmdVerbose {
		logLevel = zerolog.DebugLevel
	}
	return logging.NewZeroLogger(zerolog.Logger{}.
		Level(logLevel).
		Output(zerolog.ConsoleWriter{Out: os.Stderr}).
		With().Timestamp().Logger())
}

func init() {
	rootCmdVerbose = rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Sets log level to DEBUG")
	rootCmd.PersistentFlags().StringSliceVarP(&rootCmdRegoPaths, "data", "d", rootCmdRegoPaths, "Rego paths to load")
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(fixtureCmd)
}
