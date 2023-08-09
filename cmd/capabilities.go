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
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/snyk/policy-engine/pkg/policy"
)

var capabilitiesCmd = &cobra.Command{
	Use:   "capabilities",
	Short: "Output OPA-compatible capabilities document",
	RunE: func(cmd *cobra.Command, args []string) error {
		caps := policy.Capabilities()
		bytes, err := json.MarshalIndent(caps, "", "    ")
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "%s\n", string(bytes))
		return nil
	},
}
