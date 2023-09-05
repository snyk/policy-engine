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

	// Terms in the evaluation tree.
	Terms *TermTree

	// Any bad keys that we attempted to reference or failed to parse
	badKeys map[string]struct{}

	// Terms that we could not find and returned as a string.  We will
	// generate a warning for these.
	missingTerms map[string]struct{}
}

func AnalyzeModuleTree(mtree *ModuleTree) *Analysis {
	analysis := &Analysis{
		Fs:           mtree.fs,
		Modules:      map[string]*ModuleMeta{},
		Resources:    map[string]*ResourceMeta{},
		Terms:        NewTermTree(),
		badKeys:      map[string]struct{}{},
		missingTerms: map[string]struct{}{},
	}
	mtree.Walk(analysis)
	return analysis
}

func (v *Analysis) VisitModule(meta *ModuleMeta) {
	v.Modules[ModuleNameToString(meta.Name)] = meta
}

func (v *Analysis) VisitResource(name FullName, resource *ResourceMeta) {
	resourceKey := name.ToString()
	v.Resources[resourceKey] = resource
}

func (v *Analysis) VisitTerm(name FullName, term Term) {
	v.Terms.AddTerm(name, term)
}

// A dependency contains all the information we need to schedule evaluation of
// a term and where it should go in the scope of the term to be evaluated.
type dependency struct {
	// If this dependency should end up in a different place in the module tree
	// than the original term, destination should be set to a non-nil value.
	destination *FullName

	// If source is set, we will evaluate the source term before we evaluate the
	// term depending on it.
	source *FullName

	// Sometimes, rather than evaluating a term we may want to place a literal
	// value in the scope tree.  To do this, set source to nil and value to the
	// non-nil literal value.
	value *cty.Value
}

func (v *Analysis) dependencies(name FullName, term Term) []dependency {
	deps := []dependency{}
	for _, traversal := range term.Dependencies() {
		local, err := TraversalToLocalName(traversal)
		if err != nil {
			v.badKeys[TraversalToString(traversal)] = struct{}{}
			continue
		}

		full := FullName{Module: name.Module, Local: local}

		if prefix, _ := v.Terms.LookupByPrefix(full); prefix != nil {
			deps = append(deps, dependency{nil, prefix, nil})
			continue
		}

		if moduleOutput := full.AsModuleOutput(); moduleOutput != nil {
			deps = append(deps, dependency{&full, moduleOutput, nil})
			continue
		}

		if asVariable, asVar, _ := full.AsVariable(); asVar != nil {
			// Rewrite variables either as default, or as module input.
			asModuleInput := full.AsModuleInput()
			if asModuleInput != nil {
				if mtp, _ := v.Terms.LookupByPrefix(*asModuleInput); mtp != nil {
					deps = append(deps, dependency{asVar, mtp, nil})
					continue
				}
			}

			// Not module input, check that default is set.
			if prefix, _ := v.Terms.LookupByPrefix(*asVariable); prefix != nil {
				deps = append(deps, dependency{asVar, asVariable, nil})
				continue
			}
		}

		// In other cases, just use the local name.  This is sort of
		// a catch-all and we should try to not rely on this too much.
		v.missingTerms[full.ToString()] = struct{}{}
		val := cty.StringVal(LocalNameToString(local))
		deps = append(deps, dependency{&full, nil, &val})
	}
	return deps
}

// Iterate all expressions to be evaluated in the "correct" order.
func (v *Analysis) order() ([]FullName, error) {
	graph := map[string][]string{}
	v.Terms.VisitTerms(func(name FullName, term Term) {
		key := name.ToString()
		graph[key] = []string{}
		deps := v.dependencies(name, term)
		for _, dep := range deps {
			if dep.source != nil {
				graph[key] = append(graph[key], dep.source.ToString())
			}
		}
	})

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
	Modules  map[string]cty.Value

	resourceAttributes map[string]cty.Value

	phantomAttrs *phantomAttrs

	errors []error // Errors encountered during evaluation
}

func EvaluateAnalysis(analysis *Analysis) (*Evaluation, error) {
	eval := &Evaluation{
		Analysis:           analysis,
		Modules:            map[string]cty.Value{},
		resourceAttributes: map[string]cty.Value{},
		phantomAttrs:       newPhantomAttrs(),
	}

	for moduleKey := range analysis.Modules {
		eval.Modules[moduleKey] = cty.EmptyObjectVal
	}

	if err := eval.evaluate(); err != nil {
		return nil, err
	}

	return eval, nil
}

func (v *Evaluation) prepareVariables(name FullName, term Term) cty.Value {
	sparse := v.Modules[ModuleNameToString(name.Module)]
	for _, dep := range v.Analysis.dependencies(name, term) {
		if dep.destination != nil {
			var dependency cty.Value
			if dep.source != nil {
				sourceModule := ModuleNameToString(dep.source.Module)
				dependency = NestVal(
					dep.destination.Local,
					LookupVal(v.Modules[sourceModule], dep.source.Local),
				)
			} else if dep.value != nil {
				dependency = NestVal(dep.destination.Local, *dep.value)
			}
			if !dependency.IsNull() {
				sparse = MergeVal(sparse, dependency)
			}
		}
	}
	return sparse
}

func (v *Evaluation) evaluate() error {
	// Obtain order again
	order, err := v.Analysis.order()
	if err != nil {
		return err
	}

	termsByKey := map[string]Term{}
	v.Analysis.Terms.VisitTerms(func(name FullName, term Term) {
		termsByKey[name.ToString()] = term
		v.phantomAttrs.analyze(name, term)
	})

	// Evaluate terms
	for _, name := range order {
		term := termsByKey[name.ToString()]
		moduleKey := ModuleNameToString(name.Module)
		moduleMeta := v.Analysis.Modules[moduleKey]

		vars := v.prepareVariables(name, term)
		vars = MergeVal(vars, NestVal(LocalName{"path", "module"}, cty.StringVal(moduleMeta.Dir)))

		rootModule := v.Analysis.Modules[ModuleNameToString(EmptyModuleName)]
		if rootModule != nil {
			vars = MergeVal(vars, NestVal(LocalName{"path", "root"}, cty.StringVal(rootModule.Dir)))
		}

		// While we could pass policy-engine’s actual CWD as path.cwd, but this
		// would make it awkward to snapshot-test ("golden test"). Arguably, we
		// can't reasonably predict what a given terraform config expected CWD to be
		// at runtime - and the Terraform docs recommend using path.module or
		// path.root for this reason:
		// https://developer.hashicorp.com/terraform/language/expressions/references#filesystem-and-workspace-info
		vars = MergeVal(vars, NestVal(LocalName{"path", "cwd"}, cty.StringVal("/stubbed/working/directory")))

		vars = MergeVal(vars, NestVal(LocalName{"terraform", "workspace"}, cty.StringVal("default")))

		val, diags := term.Evaluate(func(expr hcl.Expression, extraVars cty.Value) (cty.Value, hcl.Diagnostics) {
			data := Data{}
			scope := lang.Scope{
				Data:     &data,
				SelfAddr: nil,
				PureOnly: false,
			}
			ctx := hcl.EvalContext{
				Functions: funcs.Override(v.Analysis.Fs, scope),
				Variables: ValToVariables(MergeVal(vars, extraVars)),
			}
			val, diags := expr.Value(&ctx)
			if diags.HasErrors() {
				val = cty.NullVal(val.Type())
			}
			return val, diags
		})

		if diags.HasErrors() {
			v.errors = append(v.errors, EvaluationError{diags})
		}

		v.resourceAttributes[name.ToString()] = val
		val = v.phantomAttrs.add(name, val)
		singleton := NestVal(name.Local, val)
		v.Modules[moduleKey] = MergeVal(v.Modules[moduleKey], singleton)
	}

	return nil
}

func (v *Evaluation) prepareResource(resourceMeta *ResourceMeta, module ModuleName, name string, val cty.Value) []models.ResourceState {
	resources := []models.ResourceState{}
	moduleKey := ModuleNameToString(module)

	resourceType := resourceMeta.Type
	if resourceMeta.Data {
		resourceType = "data." + resourceType
	}

	if val.Type().IsTupleType() {
		for idx, child := range val.AsValueSlice() {
			indexedName := fmt.Sprintf("%s[%d]", name, idx)
			resource := v.prepareResource(resourceMeta, module, indexedName, child)
			resources = append(resources, resource...)
		}
	} else {
		attrs := map[string]interface{}{}
		iface, errs := ValueToInterface(val)
		v.errors = append(v.errors, errs...)
		if obj, ok := iface.(map[string]interface{}); ok {
			attrs = obj
		}

		metaTree := cty.EmptyObjectVal
		providerConfName := ProviderConfigName(module, resourceMeta.ProviderName)
		if providerConf := LookupVal(v.Modules[moduleKey], providerConfName.Local); !providerConf.IsNull() {
			metaTree = MergeVal(
				metaTree,
				NestVal(
					[]string{"terraform", "provider_config"},
					providerConf,
				),
			)
		}

		if resourceMeta.ProviderVersionConstraint != "" {
			metaTree = MergeVal(
				metaTree,
				NestVal(
					[]string{"terraform", "provider_version_constraint"},
					cty.StringVal(resourceMeta.ProviderVersionConstraint),
				),
			)
		}

		meta := map[string]interface{}{}
		if metaVal, errs := ValueToInterface(metaTree); len(errs) == 0 {
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
			Id:           name,
			ResourceType: resourceType,
			Attributes:   attrs,
			Meta:         meta,
		})
	}

	return resources
}

type Resource struct {
	Meta  *ResourceMeta
	Model models.ResourceState
}

func (v *Evaluation) Resources() []Resource {
	resources := []Resource{}

	for resourceKey, resourceMeta := range v.Analysis.Resources {
		resourceName, err := StringToFullName(resourceKey)
		if err != nil || resourceName == nil {
			v.Analysis.badKeys[resourceKey] = struct{}{}
			continue
		}

		prepared := v.prepareResource(resourceMeta, resourceName.Module, resourceName.ToString(), v.resourceAttributes[resourceKey])
		for _, model := range prepared {
			resources = append(resources, Resource{
				Meta:  resourceMeta,
				Model: model,
			})
		}
	}

	return resources
}

// Errors returns the non-fatal errors encountered during evaluation
func (e *Evaluation) Errors() []error {
	errors := []error{}
	for badKey := range e.Analysis.badKeys {
		errors = append(errors, fmt.Errorf("%w: %v", errBadDependencyKey, badKey))
	}
	for missingTerm := range e.Analysis.missingTerms {
		errors = append(errors, MissingTermError{missingTerm})
	}
	errors = append(errors, e.errors...)
	return errors
}
