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

// This module contains utilities for parsing and traversing everything in a
// configuration tree.
package hcl_interpreter

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/spf13/afero"
	"github.com/zclconf/go-cty/cty"

	"github.com/snyk/policy-engine/pkg/internal/terraform/configs"
)

type ModuleMeta struct {
	Dir                  string
	Recurse              bool
	Filepaths            []string
	MissingRemoteModules []string
	Location             *hcl.Range
}

type ResourceMeta struct {
	Data                      bool
	Type                      string
	ProviderType              string
	ProviderName              string
	ProviderVersionConstraint string
	Multiple                  bool
	Location                  hcl.Range
	Body                      hcl.Body // For source code locations only.
}

// We load the entire tree of submodules in one pass.
type ModuleTree struct {
	fs             afero.Fs
	meta           *ModuleMeta
	config         hcl.Body // Call to the module, nil if root.
	module         *configs.Module
	variableValues map[string]cty.Value // Variables set
	children       map[string]*ModuleTree
	errors         []error // Non-fatal errors encountered during loading
}

func ParseDirectory(
	moduleRegister *TerraformModuleRegister,
	parserFs afero.Fs,
	dir string,
	varFiles []string,
) (*ModuleTree, error) {
	parser := configs.NewParser(parserFs)
	var diags hcl.Diagnostics

	primary, _, diags := parser.ConfigDirFiles(dir)
	if diags.HasErrors() {
		return nil, diags
	}

	// ConfigDirFiles will return `main.tf` rather than `foo/bar/../../main.tf`.
	// Rejoin the files using `TfFilePathJoin` to fix this.
	filepaths := make([]string, len(primary))
	for i, file := range primary {
		filepaths[i] = TfFilePathJoin(dir, filepath.Base(file))
	}

	foundVarFiles, err := findVarFiles(parserFs, dir)
	if err != nil {
		return nil, err
	}
	// The order here is important so that var files that are explicitly specified get
	// applied after any automatically-loaded var files.
	varFiles = append(foundVarFiles, varFiles...)
	return ParseFiles(moduleRegister, parserFs, true, dir, filepaths, varFiles)
}

func ParseFiles(
	moduleRegister *TerraformModuleRegister,
	parserFs afero.Fs,
	recurse bool,
	dir string,
	filepaths []string,
	varfiles []string,
) (*ModuleTree, error) {
	meta := &ModuleMeta{
		Dir:       dir,
		Recurse:   recurse,
		Filepaths: filepaths,
	}

	parser := configs.NewParser(parserFs)
	var diags hcl.Diagnostics
	parsedFiles := make([]*configs.File, 0)
	overrideFiles := make([]*configs.File, 0)

	for _, file := range filepaths {
		f, fDiags := parser.LoadConfigFile(file)
		diags = append(diags, fDiags...)
		parsedFiles = append(parsedFiles, f)
	}
	module, lDiags := configs.NewModule(parsedFiles, overrideFiles)
	diags = append(diags, lDiags...)

	// Deal with varfiles
	variableValues := map[string]cty.Value{}
	for _, varfile := range varfiles {
		values, lDiags := parser.LoadValuesFile(varfile)
		for k, v := range values {
			variableValues[k] = v
		}
		diags = append(diags, lDiags...)
	}

	errors := []error{}
	if diags.HasErrors() {
		return nil, &multierror.Error{Errors: diags.Errs()}
	}
	if module == nil {
		// Only actually throw an error if we don't have a module.  We can
		// still try and validate what we can.
		return nil, fmt.Errorf(diags.Error())
	}

	children := map[string]*ModuleTree{}
	if recurse {
		for key, moduleCall := range module.ModuleCalls {
			if body, ok := moduleCall.Config.(*hclsyntax.Body); ok {
				if attr, ok := body.Attributes["source"]; ok {
					if val, err := attr.Expr.Value(nil); err == nil && val.Type() == cty.String {
						source := val.AsString()
						childDir := TfFilePathJoin(dir, source)

						if register := moduleRegister.GetDir(source); register != nil {
							childDir = *register
						} else if !moduleIsLocal(source) {
							meta.MissingRemoteModules = append(
								meta.MissingRemoteModules,
								source,
							)
							continue
						}

						child, err := ParseDirectory(moduleRegister, parserFs, childDir, []string{})
						if err == nil {
							child.meta.Location = &moduleCall.SourceAddrRange
							child.config = moduleCall.Config
							children[key] = child
						} else {
							errors = append(
								errors,
								fmt.Errorf("Error loading submodule '%s': %s", key, err),
							)
						}
					}
				}
			}
		}
	}

	return &ModuleTree{parserFs, meta, nil, module, variableValues, children, errors}, nil
}

func (mtree *ModuleTree) Errors() []error {
	errors := make([]error, len(mtree.errors))
	copy(errors, mtree.errors)

	missingModules := mtree.meta.MissingRemoteModules
	if len(missingModules) > 0 {
		errors = append(errors, MissingRemoteSubmodulesError{mtree.meta.Dir, missingModules})
	}

	for _, child := range mtree.children {
		errors = append(errors, child.Errors()...)
	}

	return errors
}

func (mtree *ModuleTree) FilePath() string {
	if mtree.meta.Recurse {
		return mtree.meta.Dir
	} else {
		return mtree.meta.Filepaths[0]
	}
}

func (mtree *ModuleTree) LoadedFiles() []string {
	filepaths := []string{filepath.Join(mtree.meta.Dir, ".terraform")}
	if mtree.meta.Recurse {
		filepaths = append(filepaths, mtree.meta.Dir)
	}
	for _, fp := range mtree.meta.Filepaths {
		filepaths = append(filepaths, fp)
	}
	for _, child := range mtree.children {
		if child != nil {
			filepaths = append(filepaths, child.LoadedFiles()...)
		}
	}
	return filepaths
}

// Takes a module source and returns true if the module is local.
func moduleIsLocal(source string) bool {
	// Relevant bit from terraform docs:
	//    A local path must begin with either ./ or ../ to indicate that a local path
	//    is intended, to distinguish from a module registry address.
	return strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../")
}

type Visitor interface {
	VisitModule(name ModuleName, meta *ModuleMeta)
	VisitResource(name FullName, resource *ResourceMeta)
	VisitTerm(name FullName, term Term)
}

func (mtree *ModuleTree) Walk(v Visitor) {
	walkModuleTree(v, EmptyModuleName, mtree)
}

func walkModuleTree(v Visitor, moduleName ModuleName, mtree *ModuleTree) {
	v.VisitModule(moduleName, mtree.meta)
	walkModule(v, moduleName, mtree.module, mtree.variableValues)
	for key, child := range mtree.children {
		childModuleName := make([]string, len(moduleName)+1)
		copy(childModuleName, moduleName)
		childModuleName[len(moduleName)] = key

		// TODO: This is not good.  We end up walking child2 as it were child2.
		configName := FullName{moduleName, LocalName{"input", key}}
		for k, input := range TermFromBody(child.config).Attributes() {
			v.VisitTerm(configName.Add(k), input)
		}

		walkModuleTree(v, childModuleName, child)
	}
}

func walkModule(v Visitor, moduleName ModuleName, module *configs.Module, variableValues map[string]cty.Value) {
	name := EmptyFullName(moduleName)

	for _, variable := range module.Variables {
		if val, ok := variableValues[variable.Name]; ok {
			expr := hclsyntax.LiteralValueExpr{Val: val}
			v.VisitTerm(name.Add("variable").Add(variable.Name), TermFromExpr(&expr))
		} else if !variable.Default.IsNull() {
			expr := hclsyntax.LiteralValueExpr{
				Val:      variable.Default,
				SrcRange: variable.DeclRange,
			}
			v.VisitTerm(name.Add("variable").Add(variable.Name), TermFromExpr(&expr))
		} else {
			// If no default is provided, we can add our own default depending
			// on the type.  We currently only do this for strings.
			if variable.Type == cty.String {
				selfRef := name.Add("var").Add(variable.Name).ToString()
				expr := hclsyntax.LiteralValueExpr{
					Val:      cty.StringVal(selfRef),
					SrcRange: variable.DeclRange,
				}
				v.VisitTerm(name.Add("variable").Add(variable.Name), TermFromExpr(&expr))
			}
		}
	}

	for _, local := range module.Locals {
		v.VisitTerm(name.Add("local").Add(local.Name), TermFromExpr(local.Expr))
	}

	for _, resource := range module.DataResources {
		walkResource(v, moduleName, module, resource, true)
	}

	for _, resource := range module.ManagedResources {
		walkResource(v, moduleName, module, resource, false)
	}

	for _, output := range module.Outputs {
		if output.Expr != nil {
			v.VisitTerm(name.Add("output").Add(output.Name), TermFromExpr(output.Expr))
		}
	}

	for providerName, providerConf := range module.ProviderConfigs {
		v.VisitTerm(ProviderConfigName(moduleName, providerName), TermFromBody(providerConf.Config))
	}
}

func walkResource(
	v Visitor,
	moduleName ModuleName,
	module *configs.Module,
	resource *configs.Resource,
	isDataResource bool,
) {
	name := EmptyFullName(moduleName)
	if isDataResource {
		name = name.Add("data")
	}
	name = name.Add(resource.Type).Add(resource.Name)
	haveCount := resource.Count != nil
	haveForEach := resource.ForEach != nil

	providerName := resource.ProviderConfigAddr().StringCompact()
	resourceMeta := &ResourceMeta{
		Data:         isDataResource,
		ProviderName: providerName,
		ProviderType: resource.Provider.Type,
		Type:         resource.Type,
		Location:     resource.DeclRange,
		Multiple:     haveCount || haveForEach,
		Body:         resource.Config,
	}

	if providerReqs, ok := module.ProviderRequirements.RequiredProviders[resource.ProviderConfigAddr().LocalName]; ok {
		resourceMeta.ProviderVersionConstraint = providerReqs.Requirement.Required.String()
	}

	v.VisitResource(name, resourceMeta)

	term := TermFromBody(resource.Config)
	if haveCount {
		term = term.WithCount(resource.Count)
	} else if haveForEach {
		term = term.WithForEach(resource.ForEach)
	}

	v.VisitTerm(name, term)
}

// TfFilePathJoin is like `filepath.Join` but avoids cleaning the path.  This
// allows to get unique paths for submodules including a parent module, e.g.:
//
//	.
//	examples/mssql/../../
//	examples/complete/../../
func TfFilePathJoin(leading, trailing string) string {
	if filepath.IsAbs(trailing) {
		return trailing
	} else if leading == "." {
		return trailing
	} else {
		trailing = filepath.FromSlash(trailing)
		sep := string(filepath.Separator)
		trailing = strings.TrimPrefix(trailing, "."+sep)
		return strings.TrimRight(leading, sep) + sep +
			strings.TrimLeft(trailing, sep)
	}
}
