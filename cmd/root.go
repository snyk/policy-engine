// Copyright 2022 Snyk Ltd
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
	"io"
	"net/http"
	"os"

	"github.com/rs/zerolog"
	"github.com/snyk/policy-engine/pkg/data"
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

func rootCmdRegoProviders() []data.Provider {
	providers := []data.Provider{}
	for _, path := range rootCmdRegoPaths {
		if isTgz(path) {
			f, err := os.Open(path)
			if err != nil {
				providers = append(providers, func(ctx context.Context, consumer data.Consumer) error {
					return err
				})
			} else {
				providers = append(providers, data.TarGzProvider(f))
			}
		} else {
			providers = append(providers, data.LocalProvider(path))
		}
	}
	return providers
}

func init() {
	rootCmdVerbose = rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Sets log level to DEBUG")
	rootCmd.PersistentFlags().StringSliceVarP(&rootCmdRegoPaths, "data", "d", rootCmdRegoPaths, "Rego paths to load")
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(fixtureCmd)
	rootCmd.AddCommand(replCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(metadataCmd)
	rootCmd.AddCommand(evalCmd)
	rootCmd.AddCommand(nanovizCommand)
}
