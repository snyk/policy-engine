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

package snapshot_testing

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hexops/gotextdiff"
	"github.com/hexops/gotextdiff/myers"
	"github.com/hexops/gotextdiff/span"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
	"github.com/open-policy-agent/opa/v1/types"
)

var MatchBuiltin = &ast.Builtin{
	Name: "snapshot_testing.match",
	Decl: types.NewFunction(
		types.Args(
			types.A,
			types.S,
		),
		types.B,
	),
}

// MatchNoopImpl will always return true, and should be used everywhere except
// for actual testing.
func MatchNoopImpl() rego.BuiltinDyn {
	return func(
		bctx topdown.BuiltinContext,
		operands []*ast.Term,
	) (*ast.Term, error) {
		return ast.BooleanTerm(true), nil
	}
}

func MatchTestImpl(updateSnapshots bool) rego.BuiltinDyn {
	// One footgun that we hand to the users is the ability to specify output
	// filenames for snapshot testing.  If they have code that looks like:
	//
	//     snapshot_testing.match(["foo"], "snapshot.json")
	//     snapshot_testing.match(["bar"], "snapshot.json")
	//
	// we will overwrite the file **twice** when `--update-snapshots` is given,
	// and the second call will still fail when running the tests.  This is why
	// save the content of the values we wrote, so we can detect these duplicate
	// non-idempotent writes and display a nice diff.
	updatedSnapshots := map[string]string{}

	return func(
		bctx topdown.BuiltinContext,
		operands []*ast.Term,
	) (*ast.Term, error) {
		if len(operands) != 2 {
			return nil, fmt.Errorf("Expected two arguments")
		}

		// Serialize first argument to JSON
		val, err := ast.JSON(operands[0].Value)
		if err != nil {
			return nil, err
		}
		actualBytes, err := json.MarshalIndent(val, "", "  ")
		if err != nil {
			return nil, err
		}
		actualBytes = append(actualBytes, '\n')
		actual := string(actualBytes)

		// Infer location of snapshot file from second argument and
		// test source location
		testPath := bctx.Location.File
		relativePath, err := builtins.StringOperand(operands[1].Value, 1)
		if err != nil {
			return nil, err
		}
		snapshotPath := filepath.Join(filepath.Dir(testPath), string(relativePath))

		if updateSnapshots {
			// Update snapshot on disk
			if err := os.MkdirAll(filepath.Dir(snapshotPath), 0755); err != nil {
				return nil, err
			}
			if err := os.WriteFile(snapshotPath, actualBytes, 0644); err != nil {
				return nil, err
			}

			// Check for duplicate writes
			if snapshot, ok := updatedSnapshots[snapshotPath]; ok {
				return checkAndDisplayDiff(
					fmt.Sprintf("%s: inconsistent writes to snapshot", bctx.Location.String()),
					snapshotPath,
					snapshot,
					"actual",
					actual,
				)
			} else {
				updatedSnapshots[snapshotPath] = actual
				return ast.BooleanTerm(true), nil
			}
		} else {
			// Compare against snapshot on disk
			expected := ""
			if bytes, err := os.ReadFile(snapshotPath); err == nil {
				expected = string(bytes)
			}
			return checkAndDisplayDiff(
				fmt.Sprintf("%s: snapshots do not match", bctx.Location.String()),
				snapshotPath,
				expected,
				"actual",
				actual,
			)
		}
	}
}

// Check and print diff
func checkAndDisplayDiff(
	header string,
	expectedPath string,
	expected string,
	actualPath string,
	actual string,
) (*ast.Term, error) {
	if actual == expected {
		return ast.BooleanTerm(true), nil
	}

	edits := myers.ComputeEdits(span.URI(expectedPath), expected, actual)
	diff := gotextdiff.ToUnified(expectedPath, actualPath, expected, edits)
	fmt.Fprintf(os.Stderr, "%s:\n%s", header, diff)
	return ast.BooleanTerm(false), nil
}

// Registers MatchNoopImpl globally.
func GlobalRegisterNoop() {
	rego.RegisterBuiltinDyn(
		&rego.Function{
			Name:    MatchBuiltin.Name,
			Decl:    MatchBuiltin.Decl,
			Memoize: false,
		},
		MatchNoopImpl(),
	)
}
