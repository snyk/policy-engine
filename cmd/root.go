package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/rs/zerolog"
	"github.com/snyk/policy-engine/pkg/logging"
	"github.com/spf13/cobra"
)

func check(errs ...error) {
	nonNil := []error{}
	for _, err := range errs {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			nonNil = append(nonNil, err)
		}
	}
	if len(nonNil) > 0 {
		os.Exit(1)
	}
}

var (
	rootCmdRegoPaths []string
	rootCmdVerbose   *bool
)

var rootCmd = &cobra.Command{
	Use:   "policy-engine",
	Short: "Policy Engine",
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

func peek(r io.ReadSeeker, n int) []byte {
	buf := make([]byte, n)
	_, err := r.Read(buf)
	check(err)
	r.Seek(0, io.SeekStart)
	return buf
}

func mimeType(path string) string {
	f, err := os.Open(path)
	check(err)
	defer f.Close()
	buf := peek(f, 512)
	return http.DetectContentType(buf)
}

func isTgz(path string) bool {
	info, err := os.Stat(path)
	check(err)
	if info.IsDir() {
		return false
	}
	m := mimeType(path)
	return m == "application/x-gzip" || m == "application/gzip"
}

func init() {
	rootCmdVerbose = rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Sets log level to DEBUG")
	rootCmd.PersistentFlags().StringSliceVarP(&rootCmdRegoPaths, "data", "d", rootCmdRegoPaths, "Rego paths to load")
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(fixtureCmd)
	rootCmd.AddCommand(replCmd)
}
