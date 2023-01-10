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

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/spf13/cobra"

	"github.com/snyk/policy-engine/pkg/data"
	"github.com/snyk/policy-engine/pkg/engine"
	"github.com/snyk/policy-engine/pkg/policy"
	"github.com/snyk/policy-engine/pkg/snapshot_testing"
)

var (
	cmdEvalInput []string
)

var evalCmd = &cobra.Command{
	Use:   "eval [-d <rules/metadata>...] eval [-i input] [query]",
	Short: "Evaluate a query",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		logger := cmdLogger()
		snapshot_testing.GlobalRegisterNoop()
		consumer := engine.NewPolicyConsumer()

		regoOptions := []func(r *rego.Rego){}

		if len(cmdEvalInput) > 1 {
			return fmt.Errorf("Expected at most 1 input")
		} else if len(cmdEvalInput) == 1 {
			inputState, err := loadSingleInput(ctx, logger, cmdEvalInput[0])
			if err != nil {
				return err
			}
			replInput, err := jsonMarshalUnmarshal(inputState)
			if err != nil {
				return err
			}
			regoOptions = append(regoOptions, rego.Input(replInput))
		}

		providers := []data.Provider{
			data.PureRegoBuiltinsProvider(),
			data.PureRegoLibProvider(),
		}
		providers = append(providers, rootCmdRegoProviders()...)
		for _, provider := range providers {
			if err := provider(ctx, consumer); err != nil {
				return err
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
		regoOptions = append(regoOptions, rego.Store(store))

		compiler := ast.NewCompiler().WithCapabilities(policy.Capabilities())
		compiler.Compile(consumer.Modules)
		regoOptions = append(regoOptions, rego.Compiler(compiler))

		if len(args) != 1 {
			return fmt.Errorf("Expected exactly one query argument")
		} else {
			regoOptions = append(regoOptions, rego.Query(args[0]))
		}

		query, err := rego.New(regoOptions...).PrepareForEval(ctx)
		if err != nil {
			return err
		}
		resultSet, err := query.Eval(ctx)
		if err != nil {
			return err
		}
		bytes, err := json.Marshal(resultSet)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "%s\n", string(bytes))
		return nil
	},
}

func init() {
	evalCmd.Flags().StringSliceVarP(&cmdEvalInput, "input", "i", nil, "input file or directory")
}
