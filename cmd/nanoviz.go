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

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/snyk/policy-engine/pkg/data"
	"github.com/snyk/policy-engine/pkg/engine"
	"github.com/snyk/policy-engine/pkg/input"
	"github.com/snyk/policy-engine/pkg/snapshot_testing"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

var nanovizCommand = &cobra.Command{
	Use:   "nanoviz [-d <rules/metadata>...] [input]",
	Short: "write resources in graphviz format",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		snapshot_testing.GlobalRegisterNoop()
		consumer := engine.NewPolicyConsumer()
		if len(args) > 1 {
			return fmt.Errorf("Expected at most 1 input")
		}

		detector, err := input.DetectorByInputTypes(input.Types{input.Auto})
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
		parsedInput, err := engine.StateToParsedInput(&states[0])
		if err != nil {
			return err
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

		// NOTE: we could save some "bandwidth" by only grabbing the right keys
		// from the forward table rather than the whole resources by using a
		// slightly more complex query.
		regoOpts := []func(*rego.Rego){
			rego.Store(store),
			rego.ParsedInput(parsedInput),
			rego.Query("data.snyk.internal.relations.export"),
		}
		for _, m := range consumer.Modules {
			regoOpts = append(regoOpts, rego.ParsedModule(m))
		}

		resultSet, err := rego.New(regoOpts...).Eval(ctx)
		fmt.Fprintf(os.Stderr, "%v\n", resultSet)

		return nil
	},
}

type relationsExport map[string]relationsExportRelation
type relationsExportRelation map[[3]string][]([][3]string)

// unmarshalResultSet is a small utility function to extract the correct types out of
// a ResultSet.
func unmarshalResultSet(resultSet rego.ResultSet, v interface{}) error {
	if len(resultSet) < 1 {
		return nil
	}
	if len(resultSet[0].Expressions) < 1 {
		return nil
	}
	data, err := json.Marshal(resultSet[0].Expressions[0].Value)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
