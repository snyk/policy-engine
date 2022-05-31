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
const inputResourceTypesName = "__input_resource_types"

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
	inputResourceTypesName: types.NewFunction(
		types.Args(),
		types.NewSet(types.S),
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

type builtin interface {
	decl() *rego.Function
	impl(bctx rego.BuiltinContext, operands []*ast.Term) (*ast.Term, error)
}

type resourcesByType struct {
	calledWith map[string]bool
	input      *models.State
}

func newResourcesByType(input *models.State) *resourcesByType {
	return &resourcesByType{
		calledWith: map[string]bool{},
		input:      input,
	}
}

func (r *resourcesByType) decl() *rego.Function {
	return &rego.Function{
		Name:    resourcesByTypeName,
		Decl:    builtinDeclarations[resourcesByTypeName],
		Memoize: true,
	}
}

func (r *resourcesByType) impl(
	bctx rego.BuiltinContext,
	operands []*ast.Term,
) (*ast.Term, error) {
	if len(operands) != 2 {
		return nil, fmt.Errorf("Expected one argument")
	}
	arg, err := builtins.StringOperand(operands[0].Value, 0)
	if err != nil {
		return nil, err
	}
	rt := string(arg)
	ret := map[string]map[string]interface{}{}
	if resources, ok := r.input.Resources[rt]; ok {
		for resourceKey, resource := range resources {
			ret[resourceKey] = resourceStateToRegoInput(resource)
		}
	}
	val, err := ast.InterfaceToValue(ret)
	if err != nil {
		return nil, err
	}
	r.calledWith[rt] = true
	return ast.NewTerm(val), nil
}

func resourceStateToRegoInput(resource models.ResourceState) map[string]interface{} {
	obj := map[string]interface{}{}
	for k, attr := range resource.Attributes {
		obj[k] = attr
	}
	obj["id"] = resource.Id
	obj["_type"] = resource.ResourceType
	obj["_namespace"] = resource.Namespace
	if resource.Meta == nil {
		obj["_meta"] = map[string]interface{}{}
	} else {
		obj["_meta"] = resource.Meta
	}
	return obj
}

type currentInputType struct {
	input *models.State
}

func (c *currentInputType) decl() *rego.Function {
	return &rego.Function{
		Name:    currentInputTypeName,
		Decl:    builtinDeclarations[currentInputTypeName],
		Memoize: true,
	}
}

func (c *currentInputType) impl(
	bctx rego.BuiltinContext,
	operands []*ast.Term,
) (*ast.Term, error) {
	return ast.StringTerm(c.input.InputType), nil
}

type inputResourceTypes struct {
	input *models.State
}

func (c *inputResourceTypes) decl() *rego.Function {
	return &rego.Function{
		Name:    inputResourceTypesName,
		Decl:    builtinDeclarations[inputResourceTypesName],
		Memoize: true,
	}
}

func (c *inputResourceTypes) impl(
	bctx rego.BuiltinContext,
	operands []*ast.Term,
) (*ast.Term, error) {
	rts := make([]*ast.Term, 0, len(c.input.Resources))
	for rt := range c.input.Resources {
		rts = append(rts, ast.StringTerm(rt))
	}
	return ast.SetTerm(rts...), nil
}

type Builtins struct {
	resourcesByType *resourcesByType // We want a separate ref to this to make it cleaner to get resource types back out
	funcs           []builtin
}

func NewBuiltins(input *models.State) *Builtins {
	r := newResourcesByType(input)
	return &Builtins{
		resourcesByType: r,
		funcs: []builtin{
			r,
			&currentInputType{input},
			&inputResourceTypes{input},
		},
	}
}

func (b *Builtins) Rego() []func(*rego.Rego) {
	r := make([]func(*rego.Rego), len(b.funcs))
	for idx, f := range b.funcs {
		r[idx] = rego.FunctionDyn(f.decl(), f.impl)
	}
	return r
}

func (b *Builtins) ResourceTypes() []string {
	rts := make([]string, 0, len(b.resourcesByType.calledWith))
	for rt := range b.resourcesByType.calledWith {
		rts = append(rts, rt)
	}
	return rts
}
