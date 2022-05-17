package policy

import (
	"crypto/sha256"
	"embed"
	"fmt"
	"strings"

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
		types.NewArray(
			nil,
			types.NewObject(
				[]*types.StaticProperty{
					types.NewStaticProperty("id", types.S),
					types.NewStaticProperty("_uid", types.S),
					types.NewStaticProperty("_type", types.S),
					types.NewStaticProperty("_namespace", types.S),
				},
				types.NewDynamicProperty(types.S, types.A),
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
	ret := []map[string]interface{}{}
	if resources, ok := r.input.Resources[rt]; ok {
		ret = make([]map[string]interface{}, len(resources))
		for idx, resource := range resources {
			ret[idx] = resourceStateToRegoInput(resource)
		}
	}
	val, err := ast.InterfaceToValue(ret)
	if err != nil {
		return nil, err
	}
	r.calledWith[rt] = true
	return ast.NewTerm(val), nil
}

func hash(s string) string {
	// We're using the same procedure as OPA's crypto.sha256() builtin for consistency
	// with uids calculated in rego.
	return fmt.Sprintf("%x", sha256.Sum256([]byte(s)))
}

func calculateUid(resource models.ResourceState) string {
	return hash(
		strings.Join(
			[]string{
				hash(resource.Namespace),
				hash(resource.ResourceType),
				hash(resource.Id),
			},
			":",
		),
	)
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
	obj["_uid"] = calculateUid(resource)
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
