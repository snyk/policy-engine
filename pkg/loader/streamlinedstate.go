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

	"github.com/snyk/policy-engine/pkg/inputs"
	"github.com/snyk/policy-engine/pkg/models"
	"gopkg.in/yaml.v3"
)

type StreamlinedStateDetector struct{}

type streamlinedTfState struct {
	Skeleton  map[string]interface{}            `yaml:"_skeleton"`
	Resources map[string]map[string]interface{} `yaml:"resources"`
}

func (t *StreamlinedStateDetector) DetectFile(i InputFile, opts DetectOptions) (IACConfiguration, error) {
	if !opts.IgnoreExt && i.Ext() != ".json" {
		return nil, fmt.Errorf("%w: %v", UnrecognizedFileExtension, i.Ext())
	}
	contents, err := i.Contents()
	if err != nil {
		return nil, err
	}
	j := streamlinedTfState{}
	if err := yaml.Unmarshal(contents, &j); err != nil {
		return nil, fmt.Errorf("%w: %v", FailedToParseInput, err)
	}
	hasSkeleton := len(j.Skeleton) > 0
	hasResources := len(j.Resources) > 0

	if !hasSkeleton || !hasResources {
		return nil, fmt.Errorf("%w", InvalidInput)
	}

	var environmentProvider string
	resourcesByType := map[string]map[string]models.ResourceState{}

	for resourceKey, attributes := range j.Resources {
		if environmentProvider == "" {
			environmentProvider = strings.SplitN(resourceKey, "_", 2)[0]
		}
		resourceType := extractString(attributes, "_type")
		resources, ok := resourcesByType[resourceType]
		if !ok {
			resources = map[string]models.ResourceState{}
			resourcesByType[resourceType] = resources
		}
		resources[resourceKey] = models.ResourceState{
			Id:           extractString(attributes, "id"),
			ResourceType: resourceType,
			Namespace:    extractString(attributes, "_provider"),
			Attributes:   attributes,
			Meta: map[string]interface{}{
				"tfruntime": map[string]interface{}{
					"key": resourceKey,
				},
			},
		}
	}

	return &streamlinedStateLoader{
		path:                i.Path(),
		environmentProvider: environmentProvider,
		resourcesByType:     resourcesByType,
	}, nil
}

func (t *StreamlinedStateDetector) DetectDirectory(i InputDirectory, opts DetectOptions) (IACConfiguration, error) {
	return nil, nil
}

type streamlinedStateLoader struct {
	path                string
	environmentProvider string
	resourcesByType     map[string]map[string]models.ResourceState
}

func (l *streamlinedStateLoader) LoadedFiles() []string {
	return []string{l.path}
}

func (l *streamlinedStateLoader) Location(attributePath []interface{}) (LocationStack, error) {
	return nil, nil
}

func (l *streamlinedStateLoader) ToState() models.State {
	return models.State{
		// Note that this is outputting the CloudScan input type, because this type is
		// intended to be a stand-in for cloud scan until we're able to produce cloud
		// scan inputs without using the streamlined state format.
		InputType:           inputs.CloudScan.Name,
		EnvironmentProvider: l.environmentProvider,
		Resources:           l.resourcesByType,
	}
}

func extractString(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}
