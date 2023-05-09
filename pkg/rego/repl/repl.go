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

package repl

import (
	"context"
	"os"
	"path/filepath"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/repl"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"

	"github.com/snyk/policy-engine/pkg/data"
	"github.com/snyk/policy-engine/pkg/engine"
	"github.com/snyk/policy-engine/pkg/policy"
	"github.com/snyk/policy-engine/pkg/snapshot_testing"
)

type Options struct {
	Providers []data.Provider
	Init      []string
	Input     map[string]interface{}
}

func Repl(ctx context.Context, options Options) error {
	snapshot_testing.GlobalRegisterNoop()
	consumer := engine.NewPolicyConsumer()
	var err error
	consumer.DataDocument(
		ctx,
		"repl/input/state.json",
		map[string]interface{}{
			"repl": map[string]interface{}{
				"input": options.Input,
			},
		},
	)
	providers := []data.Provider{
		data.PureRegoBuiltinsProvider(),
		data.PureRegoLibProvider(),
	}
	providers = append(providers, options.Providers...)
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
	).WithCapabilities(policy.Capabilities())

	r.OneShot(ctx, "strict-builtin-errors")
	for _, command := range options.Init {
		if err := r.OneShot(ctx, command); err != nil {
			return err
		}
	}

	r.Loop(ctx)
	return nil
}
