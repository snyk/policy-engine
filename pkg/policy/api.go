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

package policy

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"os"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/types"
	"github.com/snyk/policy-engine/pkg/data"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/policy/inferattributes"
)

// Builtins not available to policy runners.
var unsafeBuiltins = map[string]struct{}{
	"http.send": {},
}

//go:embed regoapi
var regoApi embed.FS

// RegoAPIProvider is a provider for the embedded 'snyk' and 'fugue' Rego APIs.
var RegoAPIProvider = data.FSProvider(regoApi, "regoapi")

// ResourcesQuery describes a request for a specific resource type from the given scope.
// An empty scope is interpreted as the scope of the current input.
type ResourcesQuery struct {
	ResourceType string            `json:"resource_type"`
	Scope        map[string]string `json:"scope"`
}

// ResourcesResult contains an indication of whether the Scope specified in the
// ResourcesQuery was found and a slice of resources.
type ResourcesResult struct {
	ScopeFound bool
	Resources  []models.ResourceState
}

type ResourcesResolver func(ctx context.Context, req ResourcesQuery) (ResourcesResult, error)

func (l ResourcesResolver) And(r ResourcesResolver) ResourcesResolver {
	return func(ctx context.Context, req ResourcesQuery) (ResourcesResult, error) {
		result := ResourcesResult{
			ScopeFound: false,
			Resources:  []models.ResourceState{},
		}
		lresult, err := l(ctx, req)
		if err != nil {
			return result, err
		}
		result.ScopeFound = result.ScopeFound || lresult.ScopeFound
		result.Resources = append(result.Resources, lresult.Resources...)
		rresult, err := r(ctx, req)
		if err != nil {
			return result, err
		}
		result.ScopeFound = result.ScopeFound || rresult.ScopeFound
		result.Resources = append(result.Resources, rresult.Resources...)
		return result, nil
	}
}

func (l ResourcesResolver) Or(r ResourcesResolver) ResourcesResolver {
	return func(ctx context.Context, req ResourcesQuery) (ResourcesResult, error) {
		result := ResourcesResult{
			ScopeFound: false,
			Resources:  []models.ResourceState{},
		}
		lresult, err := l(ctx, req)
		if err != nil {
			return result, err
		}
		result.ScopeFound = result.ScopeFound || lresult.ScopeFound
		result.Resources = append(result.Resources, lresult.Resources...)
		if result.ScopeFound {
			return result, nil
		}
		rresult, err := r(ctx, req)
		if err != nil {
			return result, err
		}
		result.ScopeFound = result.ScopeFound || rresult.ScopeFound
		result.Resources = append(result.Resources, rresult.Resources...)
		return result, nil
	}
}

// Constants for builtin functions
const resourcesByTypeName = "__resources_by_type"
const currentInputTypeName = "__current_input_type"
const inputResourceTypesName = "__input_resource_types"
const queryName = "__query"

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
						types.NewStaticProperty("_id", types.S),
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
	queryName: types.NewFunction(
		types.Args(
			types.NewObject(
				[]*types.StaticProperty{
					types.NewStaticProperty("resource_type", types.S),
					types.NewStaticProperty("scope", types.NewObject(
						nil,
						types.NewDynamicProperty(types.S, types.S),
					)),
				},
				nil,
			),
		),
		types.NewArray(nil, types.NewObject(
			nil,
			types.NewDynamicProperty(types.S, types.A),
		)),
	),
}

// Capabilities returns a Capabilities that includes the the policy engine builtins.
func Capabilities() *ast.Capabilities {
	builtins := []*ast.Builtin{}
	for name, decl := range builtinDeclarations {
		builtins = append(builtins, &ast.Builtin{
			Name: name,
			Decl: decl,
		})
	}
	base := ast.CapabilitiesForThisVersion()
	for _, builtin := range base.Builtins {
    	fmt.Fprintf(os.Stderr, "%s\n", builtin.Name)
		if _, unsafe := unsafeBuiltins[builtin.Name]; !unsafe {
			builtins = append(builtins, builtin)
		}
	}
	return &ast.Capabilities{
		Builtins:       builtins,
		AllowNet:       []string{},
		FutureKeywords: base.FutureKeywords,
	}
}

type builtin interface {
	name() string
	decl() *types.Function
	impl(bctx topdown.BuiltinContext, operands []*ast.Term) (*ast.Term, error)
}

type resourcesByType struct {
	calledWith map[string]bool
	input      *models.State
}

func (r *resourcesByType) name() string {
	return resourcesByTypeName
}

func (r *resourcesByType) decl() *types.Function {
	return builtinDeclarations[resourcesByTypeName]
}

func (r *resourcesByType) impl(
	bctx topdown.BuiltinContext,
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
	ret := [][2]*ast.Term{}
	if resources, ok := r.input.Resources[rt]; ok {
		for resourceKey, resource := range resources {
			resource, err := resourceStateToRegoInput(resource)
			if err != nil {
				return nil, err
			}
			ret = append(ret, [2]*ast.Term{ast.StringTerm(resourceKey), resource})
		}
	}
	term := ast.ObjectTerm(ret...)
	r.calledWith[rt] = true
	return term, nil
}

func resourceStateToRegoInput(resource models.ResourceState) (*ast.Term, error) {
	obj := map[string]interface{}{}
	obj["id"] = resource.Id
	obj["_id"] = resource.Id
	obj["_type"] = resource.ResourceType
	obj["_namespace"] = resource.Namespace
	if resource.Meta == nil {
		obj["_meta"] = map[string]interface{}{}
	} else {
		obj["_meta"] = resource.Meta
	}
	for k, attr := range resource.Attributes {
		// If we have a non-null, non-blank ID from the resource, we should
		// retain that value. Otherwise, we should keep the logical ID that
		// we've already set.
		if k == "id" {
			if id, ok := attr.(string); ok && id != "" {
				obj[k] = attr
			}
		} else {
			obj[k] = attr
		}
	}
	val, err := ast.InterfaceToValue(obj)
	if err != nil {
		return nil, err
	}
	term := ast.NewTerm(val)
	inferattributes.DecorateResource(resource, term)
	return term, nil
}

func resourceStatesToRegoInputs(resources []models.ResourceState) ([]*ast.Term, error) {
	ret := make([]*ast.Term, len(resources))
	for i, resource := range resources {
		term, err := resourceStateToRegoInput(resource)
		if err != nil {
			return nil, err
		}
		ret[i] = term
	}
	return ret, nil
}

type currentInputType struct {
	input *models.State
}

func (c *currentInputType) name() string {
	return currentInputTypeName
}

func (c *currentInputType) decl() *types.Function {
	return builtinDeclarations[currentInputTypeName]
}

func (c *currentInputType) impl(
	bctx topdown.BuiltinContext,
	operands []*ast.Term,
) (*ast.Term, error) {
	return ast.StringTerm(c.input.InputType), nil
}

type inputResourceTypes struct {
	input *models.State
}

func (c *inputResourceTypes) name() string {
	return inputResourceTypesName
}

func (c *inputResourceTypes) decl() *types.Function {
	return builtinDeclarations[inputResourceTypesName]
}

func (c *inputResourceTypes) impl(
	bctx topdown.BuiltinContext,
	operands []*ast.Term,
) (*ast.Term, error) {
	rts := make([]*ast.Term, 0, len(c.input.Resources))
	for rt := range c.input.Resources {
		rts = append(rts, ast.StringTerm(rt))
	}
	return ast.SetTerm(rts...), nil
}

type Builtins struct {
	resourcesQueried map[string]bool // We want a separate ref to this to make it cleaner to get resource types back out
	funcs            []builtin
}

func NewBuiltins(input *models.State, resourcesResolver ResourcesResolver) *Builtins {
	// Share the same calledWith map across resource-querying builtins, so that
	// all queried resources are returned by inputResourceTypes
	inputResolver := newInputResolver(input)
	resourcesByType := &resourcesByType{input: input, calledWith: inputResolver.calledWith}
	resolver := ResourcesResolver(inputResolver.resolve)
	if resourcesResolver != nil {
		resolver = resolver.Or(resourcesResolver)
	}

	return &Builtins{
		resourcesQueried: inputResolver.calledWith,
		funcs: []builtin{
			&Query{ResourcesResolver: resolver},
			&currentInputType{input},
			&inputResourceTypes{input},
			resourcesByType,
		},
	}
}

func (b *Builtins) Rego() []func(*rego.Rego) {
	r := make([]func(*rego.Rego), len(b.funcs))
	for idx, f := range b.funcs {
		r[idx] = rego.FunctionDyn(&rego.Function{
			Name: f.name(),
			Decl: f.decl(),
		}, f.impl)
	}
	return r
}

func (b *Builtins) Implementations() map[string]*topdown.Builtin {
	m := map[string]*topdown.Builtin{}
	for _, f := range b.funcs {
		name := f.name()
		impl := f.impl
		m[f.name()] = &topdown.Builtin{
			Decl: &ast.Builtin{
				Name: name,
				Decl: f.decl(),
			},
			Func: func(bctx topdown.BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {
				result, err := impl(bctx, operands)
				if err != nil {
					return &topdown.Error{
						Code:     topdown.BuiltinErr,
						Message:  fmt.Sprintf("%v: %v", name, err.Error()),
						Location: bctx.Location,
					}
				}
				if result == nil {
					return nil
				}
				return iter(result)
			},
		}
	}
	return m
}

func (b *Builtins) ResourceTypes() []string {
	rts := make([]string, 0, len(b.resourcesQueried))
	for rt := range b.resourcesQueried {
		rts = append(rts, rt)
	}
	sort.Strings(rts)
	return rts
}
