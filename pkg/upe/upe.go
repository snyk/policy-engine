package upe

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fugue/regula/v2/pkg/rego"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/topdown"
)

type UpeOptions struct {
	Providers []rego.RegoProvider
	Builtins  map[string]*topdown.Builtin
}

type Upe struct {
	packages []string
	builtins map[string]*topdown.Builtin
	compiler *ast.Compiler
	store    storage.Store
}

func LoadUpe(ctx context.Context, options UpeOptions) (*Upe, error) {
	upe := Upe{
		packages: []string{},
		builtins: options.Builtins,
		compiler: ast.NewCompiler(),
		store:    inmem.New(),
	}

	modules := map[string]*ast.Module{}
	for _, p := range options.Providers {
		err := p(ctx, func(r rego.RegoFile) error {
			module, err := ast.ParseModule(r.Path(), r.String())
			if err != nil {
				return err
			}
			upe.packages = append(upe.packages, module.Package.Path.String())
			modules[r.Path()] = module
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	builtins := map[string]*ast.Builtin{}
	for k, v := range upe.builtins {
		builtins[k] = v.Decl
	}
	upe.compiler = upe.compiler.WithBuiltins(builtins)

	fmt.Fprintf(os.Stderr, "Compiling %d modules\n", len(modules))
	upe.compiler.Compile(modules)
	if len(upe.compiler.Errors) > 0 {
		fmt.Fprintf(os.Stderr, "Some errors in compilation")
		return nil, fmt.Errorf("%s", upe.compiler.Errors.Error())
	}
	return &upe, nil
}

// IterateRules goes through the loaded rule names.
func (upe *Upe) IterateRules() []string {
	rules := []string{}
	for _, str := range upe.packages {
		parts := strings.SplitN(str, ".", 4)
		if len(parts) == 3 && parts[0] == "data" && parts[1] == "rules" {
			rules = append(rules, parts[2])
		}
	}
	return rules
}

func (upe *Upe) Eval(
	ctx context.Context,
	overrides map[string]topdown.BuiltinFunc,
	input interface{},
	ref string,
	output interface{},
) error {
	fmt.Fprintf(os.Stderr, "Evaluating %s\n", ref)
	queryBody, err := ast.ParseBody(ref)
	if err != nil {
		return err
	}

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
