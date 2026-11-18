// © 2022-2023 Snyk Limited All rights reserved.
// Copyright 2021 Fugue, Inc.
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

package input

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/snyk/policy-engine/pkg/hcl_interpreter"
	"github.com/snyk/policy-engine/pkg/models"
)

// This is the loader that supports reading files and directories of OpenTofu HCL (.tofu)
// files. The implementation is in the `./pkg/hcl_interpreter/` package in this
// repository: this file just wraps that. That directory also contains a
// README explaining how everything fits together.
type OpenTofuDetector struct{}

func (t *OpenTofuDetector) DetectFile(i *File, opts DetectOptions) (IACConfiguration, error) {
	if !opts.IgnoreExt && !hasOpenTofuExt(i.Path) {
		return nil, fmt.Errorf("%w: %v", UnrecognizedFileExtension, i.Ext())
	}
	dir := filepath.Dir(i.Path)
	moduleTree,
		err := hcl_interpreter.ParseFiles(
		nil,
		i.Fs,
		false,
		dir,
		hcl_interpreter.EmptyModuleName,
		[]string{i.Path},
		opts.VarFiles,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", FailedToParseInput, err)
	}

	return newOpenTofuConfiguration(moduleTree)
}

func (t *OpenTofuDetector) DetectDirectory(i *Directory, opts DetectOptions) (IACConfiguration, error) {
	// First check that a `.tofu` file exists in the directory.
	tofuExists := false
	children, err := i.Children()
	if err != nil {
		return nil, err
	}
	for _, child := range children {
		if c, ok := child.(*File); ok && hasOpenTofuExt(c.Path) {
			tofuExists = true
		}
	}
	if !tofuExists {
		return nil, nil
	}

	moduleRegister := hcl_interpreter.NewTerraformRegister(i.Fs, i.Path)
	moduleTree, err := hcl_interpreter.ParseDirectory(
		moduleRegister,
		i.Fs,
		i.Path,
		hcl_interpreter.EmptyModuleName,
		opts.VarFiles,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", FailedToParseInput, err)
	}

	return newOpenTofuConfiguration(moduleTree)
}

type OpenTofuConfiguration struct {
	moduleTree *hcl_interpreter.ModuleTree
	evaluation *hcl_interpreter.Evaluation
	resources  map[string]map[string]models.ResourceState
}

func newOpenTofuConfiguration(moduleTree *hcl_interpreter.ModuleTree) (*OpenTofuConfiguration, error) {
	analysis := hcl_interpreter.AnalyzeModuleTree(moduleTree)
	evaluation, err := hcl_interpreter.EvaluateAnalysis(analysis)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", FailedToParseInput, err)
	}

	evaluationResources := evaluation.Resources()
	resources := make([]models.ResourceState, len(evaluationResources))
	for i := range evaluationResources {
		resources[i] = evaluationResources[i].Model
	}

	namespace := moduleTree.FilePath()
	for i := range resources {
		resources[i].Namespace = namespace
		resources[i].Tags = tfExtractTags(resources[i])
	}

	return &OpenTofuConfiguration{
		moduleTree: moduleTree,
		evaluation: evaluation,
		resources:  groupResourcesByType(resources),
	}, nil
}

func (c *OpenTofuConfiguration) LoadedFiles() []string {
	return c.moduleTree.LoadedFiles()
}

func (c *OpenTofuConfiguration) Location(path []interface{}) (LocationStack, error) {
	// Format is {resourceNamespace, resourceType, resourceId, attributePath...}
	if len(path) < 3 {
		return nil, nil
	}

	resourceId, ok := path[2].(string)
	if !ok {
		return nil, fmt.Errorf("Expected string resource ID in path")
	}

	ranges := c.evaluation.Location(resourceId, path[3:])
	locs := LocationStack{}
	for _, r := range ranges {
		locs = append(locs, Location{
			Path: r.Filename,
			Line: r.Start.Line,
			Col:  r.Start.Column,
		})
	}
	return locs, nil
}

func (c *OpenTofuConfiguration) ToState() models.State {
	return models.State{
		InputType:           OpenTofuHCL.Name,
		EnvironmentProvider: "iac",
		Meta: map[string]interface{}{
			"filepath": c.moduleTree.FilePath(),
		},
		Resources: c.resources,
		Scope: map[string]interface{}{
			"filepath": c.moduleTree.FilePath(),
		},
	}
}

func (c *OpenTofuConfiguration) Errors() []error {
	errors := []error{}
	errors = append(errors, c.moduleTree.Errors()...)
	errors = append(errors, c.evaluation.Errors()...)
	return errors
}

func (l *OpenTofuConfiguration) Type() *Type {
	return OpenTofuHCL
}

func hasOpenTofuExt(path string) bool {
	return strings.HasSuffix(path, ".tofu") || strings.HasSuffix(path, ".tofu.json")
}
