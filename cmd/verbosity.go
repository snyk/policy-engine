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
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"github.com/spf13/pflag"
)

// This is a helper structure that allows us to have the flags `--log-level` as
// well as `-v`, which is equivalent to `--log-level debug`.
type Verbosity struct {
	verbose  bool
	logLevel *zerolog.Level
}

// Print debug information.
func (v *Verbosity) Debug() bool {
	return v.verbose || (v.logLevel != nil && *v.logLevel == zerolog.DebugLevel)
}

// Get corresponding log level.
func (v *Verbosity) LogLevel() zerolog.Level {
	if v.logLevel != nil {
		return *v.logLevel
	}
	return defaultLogLevel
}

// Initialize flags.
func (v *Verbosity) InitFlags(flags *pflag.FlagSet) {
	flags.VarP(&verbosityVerboseFlag{&rootCmdVerbosity}, "verbose", "v", "Sets log level to debug")
	flags.Lookup("verbose").NoOptDefVal = "true"
	flags.Var(&verbosityLogLevelFlag{&rootCmdVerbosity}, "log-level", "Sets log level")
}

var logLevels = []struct {
	key   string
	level zerolog.Level
}{
	{"debug", zerolog.DebugLevel},
	{"info", zerolog.InfoLevel},
	{"warn", zerolog.WarnLevel},
	{"error", zerolog.ErrorLevel},
}

var defaultLogLevel = zerolog.InfoLevel

// pflag.Value implementation for --log-level that does validation.
type verbosityLogLevelFlag struct {
	*Verbosity
}

func (v *verbosityLogLevelFlag) String() string {
	level := v.LogLevel()
	for _, logLevel := range logLevels {
		if logLevel.level == level {
			return logLevel.key
		}
	}
	return "unknown"
}

func (v *verbosityLogLevelFlag) Set(key string) error {
	for _, logLevel := range logLevels {
		if logLevel.key == key {
			v.logLevel = &logLevel.level

			// Check consistency.
			if logLevel.level != zerolog.DebugLevel && v.verbose {
				return fmt.Errorf("expected debug when -v is set")
			}
			return nil
		}
	}
	suggestions := []string{}
	for _, logLevel := range logLevels {
		suggestions = append(suggestions, logLevel.key)
	}
	return fmt.Errorf("expected one of: %s", strings.Join(suggestions, ", "))
}

func (v *verbosityLogLevelFlag) Type() string {
	return "log-level"
}

// pflag.Value implementation for --verbose that does validation.
type verbosityVerboseFlag struct {
	*Verbosity
}

func (v *verbosityVerboseFlag) String() string {
	if v.verbose {
		return "true"
	}
	return "false"
}

func (v *verbosityVerboseFlag) Set(key string) error {
	v.verbose = true

	// Check consistency.
	if v.logLevel != nil && *v.logLevel != zerolog.DebugLevel {
		return fmt.Errorf("log-level must be set to debug")
	}
	return nil
}

func (v *verbosityVerboseFlag) Type() string {
	return "bool"
}
