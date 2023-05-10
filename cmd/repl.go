// © 2022-2023 Snyk Limited All rights reserved.
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
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/rego/repl"
)

var replFlags struct {
	Init  []string
	Cloud cloudOptions
}

var replCmd = &cobra.Command{
	Use:   "repl [-d <rules/metadata>...] [input]",
	Short: "Policy Engine",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		logger := cmdLogger()
		var inputState *models.State
		var err error
		if len(args) > 1 {
			return fmt.Errorf("expected at most 1 input")
		} else if len(args) == 1 {
			inputState, err = loadSingleInput(ctx, logger, args[0])
		} else if replFlags.Cloud.enabled() {
			inputState, err = getCloudStates(ctx, replFlags.Cloud)
		}
		if err != nil {
			return err
		}
		replInput, err := jsonMarshalUnmarshal(inputState)
		if err != nil {
			return err
		}
		err = repl.Repl(ctx, repl.Options{
			Providers: rootCmdRegoProviders(),
			Init:      replFlags.Init,
			Input:     replInput,
		})
		if err != nil {
			return err
		}

		return nil
	},
}

func jsonMarshalUnmarshal(v interface{}) (map[string]interface{}, error) {
	if b, err := json.Marshal(v); err != nil {
		return nil, err
	} else {
		out := map[string]interface{}{}
		if err := json.Unmarshal(b, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
}

func init() {
	replCmd.Flags().StringSliceVarP(&replFlags.Init, "init", "i", nil, "execute Rego statement(s) before starting REPL")
	replFlags.Cloud.addFlags(replCmd)
}
