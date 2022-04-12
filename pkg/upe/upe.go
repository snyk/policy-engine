package upe

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/topdown"

	"github.com/snyk/unified-policy-engine/pkg/rego"
)

type UpeOptions struct {
	Providers []rego.Provider
	Builtins  map[string]*topdown.Builtin
}

type Upe struct {
	packages []ast.Ref
	builtins map[string]*topdown.Builtin
	compiler *ast.Compiler
	store    storage.Store
}

func LoadUpe(ctx context.Context, options UpeOptions) (*Upe, error) {
	regoFiles := rego.NewBaseConsumer()
	for _, p := range options.Providers {
		if err := p(ctx, regoFiles); err != nil {
			return nil, err
		}
	}

	upe := Upe{
		packages: []ast.Ref{},
		builtins: options.Builtins,
		compiler: ast.NewCompiler(),
		store:    inmem.NewFromObject(regoFiles.Documents),
	}

	builtins := map[string]*ast.Builtin{}
	for k, v := range upe.builtins {
		builtins[k] = v.Decl
	}
	upe.compiler = upe.compiler.WithBuiltins(builtins)

	fmt.Fprintf(os.Stderr, "Compiling %d modules\n", len(regoFiles.Modules))
	for _, module := range regoFiles.Modules {
		// Needs to be sorted.
		upe.packages = append(upe.packages, module.Package.Path)
	}
	// Sort to get deterministic output.
	sort.Slice(upe.packages, func(i, j int) bool {
		return upe.packages[i].Compare(upe.packages[j]) < 0
	})
	upe.compiler.Compile(regoFiles.Modules)
	if len(upe.compiler.Errors) > 0 {
		fmt.Fprintf(os.Stderr, "Some errors in compilation")
		return nil, fmt.Errorf("%s", upe.compiler.Errors.Error())
	}
	return &upe, nil
}

type RuleInfo struct {
	Name      string
	InputType string
	Module    ast.Ref
	Metadata  RuleMetadata
}

type RuleMetadata struct {
	Description string `json:"description"`
}

// IterateRules goes through the loaded rule names.
func (upe *Upe) IterateRules(ctx context.Context) []RuleInfo {
	rules := []RuleInfo{}
	for _, pkg := range upe.packages {
		if len(pkg) == 4 &&
			pkg[0].Equal(ast.DefaultRootDocument) &&
			pkg[1].Equal(ast.StringTerm("rules")) {
			if ruleName, ok := pkg[2].Value.(ast.String); ok {
				if inputType, ok := pkg[3].Value.(ast.String); ok {
					rule := RuleInfo{
						Name:      string(ruleName),
						InputType: string(inputType),
						Module:    pkg,
						Metadata:  RuleMetadata{},
					}

					// Load metadata, ignoring errors for now.
					upe.Eval(
						ctx,
						nil,
						struct{}{},
						pkg.Append(ast.StringTerm("metadata")),
						&rule.Metadata,
					)

					rules = append(rules, rule)
				}
			}
		}
	}
	return rules
}

func (upe *Upe) Eval(
	ctx context.Context,
	overrides map[string]topdown.BuiltinFunc,
	input interface{},
	ref ast.Ref,
	output interface{},
) error {
	fmt.Fprintf(os.Stderr, "Evaluating %s\n", ref.String())
	queryBody := ast.NewBody(&ast.Expr{Terms: ast.RefTerm(ref...)})

	inputValue, err := ast.InterfaceToValue(input)
	if err != nil {
		return err
	}
	inputTerm := ast.NewTerm(inputValue)

	txn, err := upe.store.NewTransaction(ctx)
	if err != nil {
		return err
	}
	defer upe.store.Abort(ctx, txn)

	if len(overrides) > 0 {
		original := map[string]topdown.BuiltinFunc{}
		for k, b := range overrides {
			original[k] = upe.builtins[k].Func
			upe.builtins[k].Func = b
		}
		defer func() {
			for k, b := range original {
				upe.builtins[k].Func = b
			}
		}()
	}

	query := topdown.NewQuery(queryBody)
	queryResult, err := query.
		WithCompiler(upe.compiler).
		WithBuiltins(upe.builtins).
		WithInput(inputTerm).
		WithStore(upe.store).
		WithTransaction(txn).
		Run(ctx)
	if err != nil {
		return err
	}

	var result *ast.Value
	for _, results := range queryResult {
		for _, r := range results {
			if result == nil {
				result = &r.Value
			} else {
				return fmt.Errorf("Eval1: expected one result but got multiple")
			}
		}
	}
	if result == nil {
		// Nothing gets written to result.
		return nil
	}

	iface, err := ast.JSON(*result)
	if err != nil {
		return err
	}
	bytes, err := json.Marshal(iface)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "result: %s\n", string(bytes))

	if err := json.Unmarshal(bytes, output); err != nil {
		return err
	}

	return nil
}
