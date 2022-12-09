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
	"strings"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/snyk/policy-engine/pkg/data"
	"github.com/snyk/policy-engine/pkg/engine"
	"github.com/snyk/policy-engine/pkg/input"
	"github.com/snyk/policy-engine/pkg/policy"
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

		regoOpts := []func(*rego.Rego){
			rego.Store(store),
			rego.ParsedInput(parsedInput),
			rego.Query("data.snyk.internal.relations.export"),
		}
		for _, m := range consumer.Modules {
			regoOpts = append(regoOpts, rego.ParsedModule(m))
		}

		resultSet, err := rego.New(regoOpts...).Eval(ctx)
		if err != nil {
			return err
		}
		relations, err := parseRelations(resultSet)
		if err != nil {
			return err
		}

		fmt.Fprintf(os.Stdout, ToDot(relations))
		return nil
	},
}

type Relations map[policy.ResourceKey]ResourceRelations

type ResourceRelations map[string][]policy.ResourceKey

// parseRelations is a small utility function to extract the correct types out of
// a ResultSet.
func parseRelations(resultSet rego.ResultSet) (Relations, error) {
	// this mirrors the shape of the 'data.snyk.internal.relations.export' query
	type relationsExportRelation struct {
		LeftKey   [3]string   `json:"left_key"`
		RightKeys [][3]string `json:"right_keys"`
	}
	type relationsExport struct {
		Relations map[string][]relationsExportRelation `json:"relations"`
		Resources [][3]string                          `json:"resources"`
	}

	parseKey := func(k [3]string) policy.ResourceKey {
		return policy.ResourceKey{
			Namespace: k[0],
			Type:      k[1],
			ID:        k[2],
		}
	}

	if len(resultSet) < 1 {
		return nil, fmt.Errorf("No results for query")
	}
	if len(resultSet[0].Expressions) < 1 {
		return nil, fmt.Errorf("No result expression found")
	}
	data, err := json.Marshal(resultSet[0].Expressions[0].Value)
	if err != nil {
		return nil, err
	}
	export := relationsExport{}
	if err := json.Unmarshal(data, &export); err != nil {
		return nil, err
	}

	relations := Relations{}
	for _, resource := range export.Resources {
		relations[parseKey(resource)] = ResourceRelations{}
	}
	for name, rels := range export.Relations {
		for _, rel := range rels {
			leftKey := parseKey(rel.LeftKey)
			for _, rightKey := range rel.RightKeys {
				relations[leftKey][name] = append(
					relations[leftKey][name],
					parseKey(rightKey),
				)
			}
		}
	}

	return relations, nil
}

func ToDot(relations Relations) string {
	nodeNames := map[policy.ResourceKey]string{}
	freshNodeName := 0
	for resource := range relations {
		nodeNames[resource] = fmt.Sprintf("node_%d", freshNodeName)
		freshNodeName += 1
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "digraph nanoviz {\n")
	for resource := range relations {
		fmt.Fprintf(&sb, "%s [label=\"%s\"];\n", nodeNames[resource], resource.ID)
	}
	for resource, rels := range relations {
		for name, rights := range rels {
			for _, right := range rights {
				fmt.Fprintf(
					&sb,
					"%s -> %s [label=\"%s\"];\n",
					nodeNames[resource],
					nodeNames[right],
					name,
				)
			}
		}
	}
	fmt.Fprintf(&sb, "}\n")
	return sb.String()
}
