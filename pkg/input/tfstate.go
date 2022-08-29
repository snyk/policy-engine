// Copyright 2022 Snyk Ltd
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
	"regexp"
	"strings"

	"github.com/snyk/policy-engine/pkg/models"
	"gopkg.in/yaml.v3"
)

type TfStateDetector struct{}

func (t *TfStateDetector) DetectFile(i *File, opts DetectOptions) (IACConfiguration, error) {
	if !opts.IgnoreExt && i.Ext() != ".json" {
		return nil, fmt.Errorf("%w: %v", UnrecognizedFileExtension, i.Ext())
	}
	contents, err := i.Contents()
	if err != nil {
		return nil, err
	}
	tfstate := tfstate_State{}
	if err := yaml.Unmarshal(contents, &tfstate); err != nil {
		return nil, fmt.Errorf("%w: %v", FailedToParseInput, err)
	}

	if tfstate.TerraformVersion == "" || tfstate.Lineage == "" {
		return nil, fmt.Errorf("%w", InvalidInput)
	}

	return &tfstateLoader{
		path:  i.Path,
		state: tfstate,
	}, nil
}

func (t *TfStateDetector) DetectDirectory(i *Directory, opts DetectOptions) (IACConfiguration, error) {
	return nil, nil
}

type tfstateLoader struct {
	path  string
	state tfstate_State
}

type tfstate_State struct {
	Version          int                `yaml:"version"`
	TerraformVersion string             `yaml:"terraform_version"`
	Resources        []tfstate_Resource `yaml:"resources"`
	Lineage          string             `yaml:"lineage"`
}

type tfstate_Resource struct {
	Mode      string                     `yaml:"mode"`
	Type      string                     `yaml:"type"`
	Name      string                     `yaml:"name"`
	Provider  string                     `yaml:"provider"`
	Instances []tfstate_ResourceInstance `yaml:"instances"`
}

type tfstate_ResourceInstance struct {
	Attributes map[string]interface{} `yaml:"attributes"`
}

func (l *tfstateLoader) LoadedFiles() []string {
	return []string{l.path}
}

func (l *tfstateLoader) Errors() []error {
	return []error{}
}

func (l *tfstateLoader) Type() *Type {
	return TerraformState
}

func (l *tfstateLoader) Location(attributePath []interface{}) (LocationStack, error) {
	return nil, nil
}

func (l *tfstateLoader) ToState() models.State {
	resources := []models.ResourceState{}
	environmentProvider := ""

	for _, resource := range l.state.Resources {
		// Set resource type
		resourceType := resource.Type
		if resource.Mode == "data" {
			resourceType = "data." + resourceType
		}

		// Parse env provider
		if environmentProvider == "" {
			environmentProvider = strings.SplitN(resource.Type, "_", 2)[0]
		}

		// Parse resource provider
		resourceProvider := resource.Provider
		resourceProviderRegex := regexp.MustCompile(`^provider\[\".*/([^/]*)\"\]$`)
		resourceProviderMatches := resourceProviderRegex.FindAllStringSubmatch(resourceProvider, 1)
		if len(resourceProviderMatches) > 0 {
			resourceProvider = resourceProviderMatches[0][1]
		}

		// Ensure attributes are available
		if len(resource.Instances) < 0 {
			continue
		}
		instance := resource.Instances[0]

		// Parse ID
		id := ""
		if val, ok := instance.Attributes["id"]; ok {
			if v, ok := val.(string); ok {
				id = v
			}
		}
		if id == "" {
			continue
		}

		// Put it all together
		resources = append(resources, models.ResourceState{
			Id:           id,
			ResourceType: resourceType,
			Namespace:    resourceProvider,
			Attributes:   instance.Attributes,
			Meta: map[string]interface{}{
				"tfstate": map[string]interface{}{
					"name": resource.Name,
				},
			},
		})
	}

	return models.State{
		InputType:           TerraformState.Name,
		EnvironmentProvider: environmentProvider,
		Resources:           groupResourcesByType(resources),
	}
}
