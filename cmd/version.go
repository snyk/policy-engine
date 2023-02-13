// Copyright 2022-2023 Snyk Ltd
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
	"os"

	"github.com/snyk/policy-engine/pkg/version"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display version",
	RunE: func(cmd *cobra.Command, args []string) error {
		v := version.GetVersionInfo()
		fmt.Fprintf(os.Stdout, "Version:\t%s\n", v.Version)
		fmt.Fprintf(os.Stdout, "OPA Version:\t%s\n", v.OPAVersion)
		revision := v.Revision
		if v.HasChanges {
			revision = fmt.Sprintf("%s*", revision)
		}
		fmt.Fprintf(os.Stdout, "Revision:\t%s\n", revision)
		return nil
	},
}
