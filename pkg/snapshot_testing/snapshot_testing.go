package snapshot_testing

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hexops/gotextdiff"
	"github.com/hexops/gotextdiff/myers"
	"github.com/hexops/gotextdiff/span"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/types"
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

func MatchImpl(updateSnapshots bool) rego.BuiltinDyn {
	return func(
		bctx rego.BuiltinContext,
		operands []*ast.Term,
	) (*ast.Term, error) {
		if len(operands) != 2 {
			return nil, fmt.Errorf("Expected two arguments")
		}

		val, err := ast.JSON(operands[0].Value)
		if err != nil {
			return nil, err
		}

		actualBytes, err := json.MarshalIndent(val, "", "  ")
		if err != nil {
			return nil, err
		}
		actual := string(actualBytes)

		testPath := bctx.Location.File
		relativePath, err := builtins.StringOperand(operands[1].Value, 1)
		if err != nil {
			return nil, err
		}
		snapshotPath := filepath.Join(filepath.Dir(testPath), string(relativePath))

		if updateSnapshots {
			if err := os.MkdirAll(filepath.Dir(snapshotPath), 0755); err != nil {
				return nil, err
			}

			if err := os.WriteFile(snapshotPath, actualBytes, 0644); err != nil {
				return nil, err
			}

			return ast.BooleanTerm(true), nil
		} else {
			expected := ""
			if bytes, err := os.ReadFile(snapshotPath); err == nil {
				expected = string(bytes)
			}

			if actual == expected {
				return ast.BooleanTerm(true), nil
			}

			edits := myers.ComputeEdits(span.URIFromPath(snapshotPath), expected, actual)
			diff := gotextdiff.ToUnified(snapshotPath, testPath, expected, edits)
			fmt.Fprintf(os.Stderr, "%s", diff)
			return ast.BooleanTerm(false), nil
		}
	}
}
