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

package loader

import (
	"fmt"
	"strings"

	"github.com/snyk/unified-policy-engine/pkg/models"
	"gopkg.in/yaml.v3"
)

type TfRuntimeDetector struct{}

type streamlinedTfState struct {
	Skeleton  map[string]interface{}            `yaml:"_skeleton"`
	Resources map[string]map[string]interface{} `yaml:"resources"`
}

func (t *TfRuntimeDetector) DetectFile(i InputFile, opts DetectOptions) (IACConfiguration, error) {
	if !opts.IgnoreExt && i.Ext() != ".json" {
		return nil, fmt.Errorf("File does not have .json extension: %v", i.Path())
	}
	contents, err := i.Contents()
	if err != nil {
		return nil, err
	}
	j := streamlinedTfState{}
	if err := yaml.Unmarshal(contents, &j); err != nil {
		return nil, fmt.Errorf("Failed to parse JSON file %v: %v", i.Path(), err)
	}
	hasSkeleton := len(j.Skeleton) > 0
	hasResources := len(j.Resources) > 0

	if !hasSkeleton || !hasResources {
		return nil, fmt.Errorf("Input file is not runtime state JSON: %v", i.Path())
	}

	var environmentProvider string
	resources := map[string]models.ResourceState{}

	for resourceKey, attributes := range j.Resources {
		if environmentProvider == "" {
			environmentProvider = strings.SplitN(resourceKey, "_", 2)[0]
		}
		resources[resourceKey] = models.ResourceState{
			Id:           attributes["id"].(string),
			ResourceType: attributes["_type"].(string),
			Namespace:    attributes["_provider"].(string),
			Attributes:   attributes,
		}
	}

	return &tfRuntimeLoader{
		path:                i.Path(),
		environmentProvider: environmentProvider,
		resources:           resources,
	}, nil
}

func (t *TfRuntimeDetector) DetectDirectory(i InputDirectory, opts DetectOptions) (IACConfiguration, error) {
	return nil, nil
}

type tfRuntimeLoader struct {
	path                string
	environmentProvider string
	resources           map[string]models.ResourceState
}

func (l *tfRuntimeLoader) RegulaInput() RegulaInput {
	return RegulaInput{}
}

func (l *tfRuntimeLoader) LoadedFiles() []string {
	return []string{l.path}
}

func (l *tfRuntimeLoader) Location(attributePath []string) (LocationStack, error) {
	return nil, nil
}

func (l *tfRuntimeLoader) ToState() models.State {
	return models.State{
		InputType:           "tf_runtime",
		EnvironmentProvider: l.environmentProvider,
		Resources:           l.resources,
	}
}
