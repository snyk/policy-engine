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
const currentInputTypeName = "__current_input_type"

var builtinDeclarations = map[string]*types.Function{
	resourcesByTypeName: types.NewFunction(
		types.Args(types.S),
		types.NewObject(
			nil,
			types.NewDynamicProperty(
				types.S,
				types.NewObject(
					[]*types.StaticProperty{
						types.NewStaticProperty("id", types.S),
						types.NewStaticProperty("_type", types.S),
						types.NewStaticProperty("_namespace", types.S),
					},
					types.NewDynamicProperty(types.S, types.A),
				),
			),
		),
	),
	currentInputTypeName: types.NewFunction(
		types.Args(),
		types.S,
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
	calledWith map[string]bool
	input      *models.State
}

func newResourcesByType(input *models.State) resourcesByType {
	return resourcesByType{
		calledWith: map[string]bool{},
		input:      input,
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
		ret := [][2]*ast.Term{}
		if resources, ok := r.input.Resources[rt]; ok {
			for resourceKey, resource := range resources {
				state, err := ast.InterfaceToValue(resourceStateToRegoInput(resource))
				if err != nil {
					return nil, err
				}
				ret = append(
					ret,
					[2]*ast.Term{
						ast.StringTerm(resourceKey),
						ast.NewTerm(state),
					},
				)
			}
		}
		r.calledWith[rt] = true
		return ast.ObjectTerm(ret...), nil
	})
}

func resourceStateToRegoInput(resource models.ResourceState) map[string]interface{} {
	obj := map[string]interface{}{}
	for k, attr := range resource.Attributes {
		obj[k] = attr
	}
	obj["id"] = resource.Id
	obj["_type"] = resource.ResourceType
	obj["_namespace"] = resource.Namespace
	return obj
}

type currentInputType struct {
	input *models.State
}

func (c *currentInputType) rego() func(*rego.Rego) {
	return rego.FunctionDyn(&rego.Function{
		Name:    currentInputTypeName,
		Decl:    builtinDeclarations[currentInputTypeName],
		Memoize: true,
	}, func(bctx rego.BuiltinContext, operands []*ast.Term) (*ast.Term, error) {
		return ast.StringTerm(c.input.InputType), nil
	})
}

type Builtins struct {
	resourcesByType
	currentInputType
}

func NewBuiltins(input *models.State) *Builtins {
	return &Builtins{
		resourcesByType:  newResourcesByType(input),
		currentInputType: currentInputType{input},
	}
}

func (b *Builtins) Rego() []func(*rego.Rego) {
	return []func(*rego.Rego){
		b.resourcesByType.rego(),
		b.currentInputType.rego(),
	}
}

func (b *Builtins) ResourceTypes() []string {
	rts := make([]string, 0, len(b.resourcesByType.calledWith))
	for rt := range b.resourcesByType.calledWith {
		rts = append(rts, rt)
	}
	return rts
}
