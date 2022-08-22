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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/repl"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/snyk/policy-engine/pkg/data"
	"github.com/snyk/policy-engine/pkg/engine"
	"github.com/snyk/policy-engine/pkg/input"
	"github.com/snyk/policy-engine/pkg/snapshot_testing"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

var (
	cmdReplInit []string
)

var replCmd = &cobra.Command{
	Use:   "repl [-d <rules/metadata>...] [input]",
	Short: "Policy Engine",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		snapshot_testing.GlobalRegisterNoop()
		consumer := engine.NewPolicyConsumer()
		if len(args) > 1 {
			return fmt.Errorf("Expected at most 1 input")
		} else if len(args) == 1 {
			detector, err := input.DetectorByInputTypes(input.Types{
				input.Auto,
				input.StreamlinedState,
			})
			if err != nil {
				return err
			}
			i, err := input.NewDetectable(afero.OsFs{}, args[0])
			if err != nil {
				return err
			}
			loader := input.NewLoader(detector)
			loaded, err := loader.Load(i, input.DetectOptions{})
			if err != nil {
				return err
			}
			if !loaded {
				return fmt.Errorf("Unable to find recognized input in %s", args[0])
			}
			states := loader.ToStates()
			if len(states) != 1 {
				return fmt.Errorf("Expected a single state but got %d", len(states))
			}
			replInput, err := jsonMarshalUnmarshal(states[0])
			if err != nil {
				return err
			}
			consumer.DataDocument(
				ctx,
				"repl/input/state.json",
				map[string]interface{}{
					"repl": map[string]interface{}{
						"input": replInput,
					},
				},
			)
		}
		if err := data.PureRegoBuiltinsProvider()(ctx, consumer); err != nil {
			return err
		}
		if err := data.PureRegoLibProvider()(ctx, consumer); err != nil {
			return err
		}
		for _, path := range rootCmdRegoPaths {
			if isTgz(path) {
				f, err := os.Open(path)
				if err != nil {
					return err
				}
				if err := data.TarGzProvider(f)(ctx, consumer); err != nil {
					return err
				}
			} else {
				if err := data.LocalProvider(path)(ctx, consumer); err != nil {
					return err
				}
			}
		}
		store := inmem.NewFromObject(consumer.Document)
		txn, err := store.NewTransaction(ctx, storage.TransactionParams{
			Write: true,
		})
		if err != nil {
			return err
		}
		for p, m := range consumer.Modules {
			store.UpsertPolicy(ctx, txn, p, []byte(m.String()))
		}
		if err = store.Commit(ctx, txn); err != nil {
			return err
		}
		var historyPath string
		if homeDir, err := os.UserHomeDir(); err == nil {
			historyPath = filepath.Join(homeDir, ".engine-history")
		} else {
			historyPath = filepath.Join(".", ".engine-history")
		}
		r := repl.New(
			store,
			historyPath,
			os.Stdout,
			"pretty",
			ast.CompileErrorLimitDefault,
			"",
		)
		r.OneShot(ctx, "strict-builtin-errors")
		for _, command := range cmdReplInit {
			if err := r.OneShot(ctx, command); err != nil {
				return err
			}
		}
		r.Loop(ctx)
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
	replCmd.Flags().StringSliceVarP(&cmdReplInit, "init", "i", nil, "execute Rego statements before starting REPL")
}
