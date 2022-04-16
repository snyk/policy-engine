package policy

import (
	"embed"
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/types"
	"github.com/snyk/unified-policy-engine/pkg/data"
	"github.com/snyk/unified-policy-engine/pkg/models"
)

//go:embed regoapi
var regoApi embed.FS

// RegoAPIProvider is a provider for the embedded 'snyk' and 'fugue' Rego APIs.
var RegoAPIProvider = data.FSProvider(regoApi, "regoapi")

// Constants for builtin functions
const resourcesByTypeName = "__resources_by_type"

var builtinDeclarations = map[string]*types.Function{
	resourcesByTypeName: types.NewFunction(
		types.Args(types.S),
		types.A,
	),
}

// Capabilities returns a Capabilities that includes the UPE builtins.
func Capabilities() *ast.Capabilities {
	builtins := []*ast.Builtin{}
	for name, decl := range builtinDeclarations {
		builtins = append(builtins, &ast.Builtin{
			Name: name,
			Decl: decl,
		})
	}
	base := ast.CapabilitiesForThisVersion()
	return &ast.Capabilities{
		Builtins:       append(base.Builtins, builtins...),
		AllowNet:       []string{},
		FutureKeywords: base.FutureKeywords,
	}
}

type resourcesByType struct {
	calledWithMissing map[string]bool
	calledWith        map[string]bool
	input             *models.State
}

func newResourcesByType(input *models.State) *resourcesByType {
	return &resourcesByType{
		calledWithMissing: map[string]bool{},
		calledWith:        map[string]bool{},
		input:             input,
	}
}

func (r *resourcesByType) rego() func(*rego.Rego) {
	return rego.FunctionDyn(&rego.Function{
		Name:    resourcesByTypeName,
		Decl:    builtinDeclarations[resourcesByTypeName],
		Memoize: true,
	}, func(bctx rego.BuiltinContext, operands []*ast.Term) (*ast.Term, error) {
		if len(operands) != 2 {
			return nil, fmt.Errorf("Expected one argument")
		}
		arg, err := builtins.StringOperand(operands[0].Value, 0)
		if err != nil {
			return nil, err
		}
		rt := string(arg)
		ret := map[string]interface{}{}
		for k, resource := range r.input.Resources {
			if resource.ResourceType == rt {
				ret[k] = resource.Attributes
			}
		}
		val, err := ast.InterfaceToValue(ret)
		if err != nil {
			return nil, err
		}
		r.calledWith[rt] = true
		if len(ret) < 1 {
			r.calledWithMissing[rt] = true
		}
		return ast.NewTerm(val), nil
	})
}

type Builtins struct {
	resourcesByType
}

func NewBuiltins(input *models.State) *Builtins {
	return &Builtins{
		resourcesByType: *newResourcesByType(input),
	}
}

func (b *Builtins) Rego() []func(*rego.Rego) {
	return []func(*rego.Rego){
		b.resourcesByType.rego(),
	}
}

func (b *Builtins) MissingResourceTypes() []string {
	rts := make([]string, 0, len(b.resourcesByType.calledWithMissing))
	for rt := range b.resourcesByType.calledWithMissing {
		rts = append(rts, rt)
	}
	return rts
}
