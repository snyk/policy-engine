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

// Look in `/pkg/hcl_interpreter/README.md` for an explanation of how this
// works.
package hcl_interpreter

import (
	"fmt"
	"github.com/hashicorp/hcl/v2"
	"github.com/spf13/afero"
	"github.com/zclconf/go-cty/cty"

	"github.com/snyk/policy-engine/pkg/hcl_interpreter/funcs"
	"github.com/snyk/policy-engine/pkg/input/schemas"
	tfschemas "github.com/snyk/policy-engine/pkg/input/schemas/tf"
	"github.com/snyk/policy-engine/pkg/internal/terraform/lang"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/topsort"
)

type Analysis struct {
	Fs afero.Fs

	// Module metadata
	Modules map[string]*ModuleMeta

	// Resource metadata
	Resources map[string]*ResourceMeta

	// Holds all keys to expressions within resources.  This is necessary if
	// we want to do dependency analysis and something depends on "all of
	// a resource".
	ResourceExpressions map[string][]FullName

	// All known expressions
	Expressions map[string]hcl.Expression

	// All known blocks
	Blocks []FullName

	// Replaces Expressions, ResourceExpressions, Blocks
	Terms *TermTree

	// Visit state: current resource (if any)
	currentResource *string

	// Any bad keys that we attempted to reference or failed to parse
	badKeys map[string]struct{}
}

func AnalyzeModuleTree(mtree *ModuleTree) *Analysis {
	analysis := &Analysis{
		Fs:                  mtree.fs,
		Modules:             map[string]*ModuleMeta{},
		Resources:           map[string]*ResourceMeta{},
		ResourceExpressions: map[string][]FullName{},
		Expressions:         map[string]hcl.Expression{},
		Blocks:              []FullName{},
		Terms:               NewTermTree(),
		currentResource:     nil,
		badKeys:             map[string]struct{}{},
	}
	mtree.Walk(analysis)
	return analysis
}

func (v *Analysis) VisitModule(name ModuleName, meta *ModuleMeta) {
	v.Modules[ModuleNameToString(name)] = meta
}

func (v *Analysis) EnterResource(name FullName, resource *ResourceMeta) {
	resourceKey := name.ToString()
	v.Resources[resourceKey] = resource
	v.ResourceExpressions[resourceKey] = []FullName{}
	v.currentResource = &resourceKey
}

func (v *Analysis) LeaveResource() {
	v.currentResource = nil
}

func (v *Analysis) VisitBlock(name FullName) {
	v.Blocks = append(v.Blocks, name)
}

func (v *Analysis) VisitExpr(name FullName, expr hcl.Expression) {
	v.Expressions[name.ToString()] = expr
	if v.currentResource != nil {
		v.ResourceExpressions[*v.currentResource] = append(
			v.ResourceExpressions[*v.currentResource],
			name,
		)
	}
}

func (v *Analysis) VisitTerm(name FullName, term Term) {
	v.Terms.AddTerm(name, term)
}

type dependency struct {
	destination FullName
	source      *FullName
	value       *cty.Value
}

// Iterate all dependencies of a the given expression with the given name.
func (v *Analysis) dependencies(name FullName, expr hcl.Expression) []dependency {
	deps := []dependency{}
	for _, traversal := range expr.Variables() {
		local, err := TraversalToLocalName(traversal)
		if err != nil {
			v.badKeys[TraversalToString(traversal)] = struct{}{}
			continue
		}
		full := FullName{Module: name.Module, Local: local}
		_, exists := v.Expressions[full.ToString()]

		if exists || full.IsBuiltin() {
			deps = append(deps, dependency{full, &full, nil})
		} else if moduleOutput := full.AsModuleOutput(); moduleOutput != nil {
			// Rewrite module outputs.
			deps = append(deps, dependency{full, moduleOutput, nil})
		} else if asVariable, asVar, _ := full.AsVariable(); asVar != nil {
			// Rewrite variables either as default, or as module input.
			asModuleInput := full.AsModuleInput()
			isModuleInput := false
			if asModuleInput != nil {
				if _, ok := v.Expressions[asModuleInput.ToString()]; ok {
					deps = append(deps, dependency{full, asModuleInput, nil})
					isModuleInput = true
				}
			}
			if !isModuleInput {
				deps = append(deps, dependency{*asVar, asVariable, nil})
			}
		} else if asResourceName, _, trailing := full.AsResourceName(); asResourceName != nil {
			// Rewrite resource references.
			resourceKey := asResourceName.ToString()
			if resourceMeta, ok := v.Resources[resourceKey]; ok {
				// Keep track of attributes already added, and add "real"
				// resource expressions.
				attrs := map[string]struct{}{}
				for _, re := range v.ResourceExpressions[resourceKey] {
					attr := re
					attrs[attr.ToString()] = struct{}{}
					deps = append(deps, dependency{attr, &attr, nil})
				}

				// There may be absent attributes as well, such as "id" and
				// "arn".  We will fill these in with the resource key.

				// Construct attribute name where we will place these.
				resourceKeyVal := cty.StringVal(resourceKey)
				resourceName := *asResourceName
				if resourceMeta.Count {
					resourceName = resourceName.AddIndex(0)
				}

				// Add attributes that are not in `attrs` yet.  Include
				// the requested one (`trailing`) as well as any possible
				// references we find in the expression (`ExprAttributes`).
				absentAttrs := ExprAttributes(expr)
				if len(trailing) > 0 {
					absentAttrs = append(absentAttrs, trailing)
				}
				for _, attr := range absentAttrs {
					attrName := resourceName.AddLocalName(attr)
					if _, ok := attrs[attrName.ToString()]; !ok {
						deps = append(deps, dependency{attrName, nil, &resourceKeyVal})
					}
				}
			} else {
				// In other cases, just use the local name.  This is sort of
				// a catch-all and we should try to not rely on this too much.
				val := cty.StringVal(LocalNameToString(local))
				deps = append(deps, dependency{full, nil, &val})
			}
		}
	}
	return deps
}

func (v *Analysis) termDependencies(name FullName, term Term) []dependency {
	deps := []dependency{}
	term.VisitExpressions(func(expr hcl.Expression) {
		for _, traversal := range expr.Variables() {
			local, err := TraversalToLocalName(traversal)
			if err != nil {
				v.badKeys[TraversalToString(traversal)] = struct{}{}
				continue
			}
			full := FullName{Module: name.Module, Local: local}
			_, exists := v.Expressions[full.ToString()]

			if exists || full.IsBuiltin() {
				deps = append(deps, dependency{full, &full, nil})
			} else if moduleOutput := full.AsModuleOutput(); moduleOutput != nil {
				// Rewrite module outputs.
				deps = append(deps, dependency{full, moduleOutput, nil})
			} else if asVariable, asVar, _ := full.AsVariable(); asVar != nil {
				// Rewrite variables either as default, or as module input.
				asModuleInput := full.AsModuleInput()
				isModuleInput := false
				if asModuleInput != nil {
					if _, ok := v.Expressions[asModuleInput.ToString()]; ok {
						deps = append(deps, dependency{full, asModuleInput, nil})
						isModuleInput = true
					}
				}
				if !isModuleInput {
					deps = append(deps, dependency{*asVar, asVariable, nil})
				}
			} else if asResourceName, _, trailing := full.AsResourceName(); asResourceName != nil {
				// Rewrite resource references.
				resourceKey := asResourceName.ToString()
				if resourceMeta, ok := v.Resources[resourceKey]; ok {
					// Keep track of attributes already added, and add "real"
					// resource expressions.
					attrs := map[string]struct{}{}
					for _, re := range v.ResourceExpressions[resourceKey] {
						attr := re
						attrs[attr.ToString()] = struct{}{}
						deps = append(deps, dependency{attr, &attr, nil})
					}

					// There may be absent attributes as well, such as "id" and
					// "arn".  We will fill these in with the resource key.

					// Construct attribute name where we will place these.
					resourceKeyVal := cty.StringVal(resourceKey)
					resourceName := *asResourceName
					if resourceMeta.Count {
						resourceName = resourceName.AddIndex(0)
					}

					// Add attributes that are not in `attrs` yet.  Include
					// the requested one (`trailing`) as well as any possible
					// references we find in the expression (`ExprAttributes`).
					absentAttrs := ExprAttributes(expr)
					if len(trailing) > 0 {
						absentAttrs = append(absentAttrs, trailing)
					}
					for _, attr := range absentAttrs {
						attrName := resourceName.AddLocalName(attr)
						if _, ok := attrs[attrName.ToString()]; !ok {
							deps = append(deps, dependency{attrName, nil, &resourceKeyVal})
						}
					}
				} else {
					// In other cases, just use the local name.  This is sort of
					// a catch-all and we should try to not rely on this too much.
					val := cty.StringVal(LocalNameToString(local))
					deps = append(deps, dependency{full, nil, &val})
				}
			}
		}
	})
	return deps
}

// Iterate all expressions to be evaluated in the "correct" order.
func (v *Analysis) order() ([]FullName, error) {
	graph := map[string][]string{}
	for key, expr := range v.Expressions {
		name, err := StringToFullName(key)
		if err != nil {
			v.badKeys[key] = struct{}{}
			continue
		}

		graph[key] = []string{}
		for _, dep := range v.dependencies(*name, expr) {
			if dep.source != nil {
				graph[key] = append(graph[key], dep.source.ToString())
			}
		}
	}

	sorted, err := topsort.Topsort(graph)
	if err != nil {
		return nil, err
	}

	sortedNames := []FullName{}
	for _, key := range sorted {
		name, err := StringToFullName(key)
		if err != nil {
			v.badKeys[key] = struct{}{}
			continue
		}
		sortedNames = append(sortedNames, *name)
	}
	return sortedNames, nil
}

type Evaluation struct {
	Analysis *Analysis
	Modules  map[string]ValTree

	errors []error // Errors encountered during evaluation
}

func EvaluateAnalysis(analysis *Analysis) (*Evaluation, error) {
	eval := &Evaluation{
		Analysis: analysis,
		Modules:  map[string]ValTree{},
	}

	for moduleKey := range analysis.Modules {
		eval.Modules[moduleKey] = EmptyObjectValTree()
	}

	if err := eval.evaluate(); err != nil {
		return nil, err
	}

	return eval, nil
}

func (v *Evaluation) prepareVariables(name FullName, expr hcl.Expression) ValTree {
	sparse := EmptyObjectValTree()
	for _, dep := range v.Analysis.dependencies(name, expr) {
		var dependency ValTree
		if dep.source != nil {
			sourceModule := ModuleNameToString(dep.source.Module)
			dependency = BuildValTree(
				dep.destination.Local,
				LookupValTree(v.Modules[sourceModule], dep.source.Local),
			)
		} else if dep.value != nil {
			dependency = SingletonValTree(dep.destination.Local, *dep.value)
		}
		if dependency != nil {
			sparse = MergeValTree(sparse, dependency)
		}
	}
	return sparse
}

func (v *Evaluation) evaluate() error {
	// Obtain order
	order, err := v.Analysis.order()
	if err != nil {
		return err
	}

	// Initialize a skeleton with blocks, to ensure empty blocks are present
	for _, name := range v.Analysis.Blocks {
		moduleKey := ModuleNameToString(name.Module)
		tree := BuildValTree(name.Local, EmptyObjectValTree())
		v.Modules[moduleKey] = MergeValTree(v.Modules[moduleKey], tree)
	}

	// Evaluate expressions
	for _, name := range order {
		expr := v.Analysis.Expressions[name.ToString()]
		moduleKey := ModuleNameToString(name.Module)
		moduleMeta := v.Analysis.Modules[moduleKey]

		vars := v.prepareVariables(name, expr)
		vars = MergeValTree(vars, SingletonValTree(LocalName{"path", "module"}, cty.StringVal(moduleMeta.Dir)))
		vars = MergeValTree(vars, SingletonValTree(LocalName{"terraform", "workspace"}, cty.StringVal("default")))

		// Add count.index if inside a counted resource.
		resourceName, _, _ := name.AsResourceName()
		if resourceName != nil {
			resourceKey := resourceName.ToString()
			if resource, ok := v.Analysis.Resources[resourceKey]; ok {
				if resource.Count {
					vars = MergeValTree(vars, SingletonValTree(LocalName{"count", "index"}, cty.NumberIntVal(0)))
				}
			}
		}

		data := Data{}
		scope := lang.Scope{
			Data:     &data,
			SelfAddr: nil,
			PureOnly: false,
		}
		ctx := hcl.EvalContext{
			Functions: funcs.Override(v.Analysis.Fs, scope),
			Variables: ValTreeToVariables(vars),
		}

		val, diags := expr.Value(&ctx)
		if diags.HasErrors() {
			v.errors = append(v.errors, fmt.Errorf("evaluate: error: %s", diags))
			val = cty.NullVal(val.Type())
		}

		singleton := SingletonValTree(name.Local, val)
		v.Modules[moduleKey] = MergeValTree(v.Modules[moduleKey], singleton)
	}

	return nil
}

func (v *Evaluation) Resources() []models.ResourceState {
	resources := []models.ResourceState{}

	for resourceKey, resource := range v.Analysis.Resources {
		resourceName, err := StringToFullName(resourceKey)
		if err != nil || resourceName == nil {
			v.Analysis.badKeys[resourceKey] = struct{}{}
			continue
		}
		module := ModuleNameToString(resourceName.Module)

		resourceType := resource.Type
		if resource.Data {
			resourceType = "data." + resourceType
		}

		resourceAttrsName := *resourceName
		if resource.Count {
			resourceAttrsName = resourceAttrsName.AddIndex(0)
		}

		attributes := LookupValTree(v.Modules[module], resourceAttrsName.Local)

		if countTree := LookupValTree(attributes, LocalName{"count"}); countTree != nil {
			if countVal, ok := countTree.(cty.Value); ok {
				count := ValueToInt(countVal)
				if count != nil && *count < 1 {
					continue
				}
			}
		}

		attrs := map[string]interface{}{}
		iface, errs := ValueToInterface(ValTreeToValue(attributes))
		v.errors = append(v.errors, errs...)
		if obj, ok := iface.(map[string]interface{}); ok {
			attrs = obj
		}

		metaTree := EmptyObjectValTree()
		providerConfName := ProviderConfigName(resourceName.Module, resource.ProviderName)
		providerConf := LookupValTree(
			v.Modules[module],
			providerConfName.Local,
		)
		if obj, ok := providerConf.(map[string]interface{}); ok && len(obj) > 0 {
			metaTree = MergeValTree(
				metaTree,
				SingletonValTree(
					[]interface{}{"terraform", "provider_config"},
					ValTreeToValue(providerConf),
				),
			)
		}

		if resource.ProviderVersionConstraint != "" {
			metaTree = MergeValTree(
				metaTree,
				SingletonValTree(
					[]interface{}{"terraform", "provider_version_constraint"},
					cty.StringVal(resource.ProviderVersionConstraint),
				),
			)
		}

		meta := map[string]interface{}{}
		if metaVal, errs := ValueToInterface(ValTreeToValue(metaTree)); len(errs) == 0 {
			if metaObj, ok := metaVal.(map[string]interface{}); ok {
				meta = metaObj
			}
		}

		// Add meta.region if present
		if tfmeta, ok := meta["terraform"].(map[string]interface{}); ok {
			if pc, ok := tfmeta["provider_config"].(map[string]interface{}); ok {
				if region, ok := pc["region"].(string); ok {
					meta["region"] = region
				}
			}
		}

		attrs = schemas.ApplyObject(attrs, tfschemas.GetSchema(resourceType))

		// TODO: Support tags again: PopulateTags(input[resourceKey])
		resources = append(resources, models.ResourceState{
			Id:           resourceKey,
			ResourceType: resourceType,
			Attributes:   attrs,
			Meta:         meta,
		})
	}

	return resources
}

// Errors returns the non-fatal errors encountered during evaluation
func (e *Evaluation) Errors() []error {
	errors := []error{}
	for _, badKey := range e.Analysis.badKeys {
		errors = append(errors, fmt.Errorf("Bad dependency key: %s", badKey))
	}
	errors = append(errors, e.errors...)
	return errors
}
