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
	"bytes"
	"fmt"
	"io"

	"github.com/snyk/policy-engine/pkg/models"
	"gopkg.in/yaml.v3"
)

var validK8sExts map[string]bool = map[string]bool{
	".json": true,
	".yaml": true,
	".yml":  true,
}

type KubernetesDetector struct{}

func (c *KubernetesDetector) DetectFile(i *File, opts DetectOptions) (IACConfiguration, error) {
	if !opts.IgnoreExt && !validK8sExts[i.Ext()] {
		return nil, fmt.Errorf("%w: %v", UnrecognizedFileExtension, i.Ext())
	}
	contents, err := i.Contents()
	if err != nil {
		return nil, err
	}
	documents, err := splitYAML(contents)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", FailedToParseInput, err)
	}

	sources := map[k8s_Key]SourceInfoNode{}
	documentSources, err := LoadMultiSourceInfoNode(contents)
	if err != nil {
		documentSources = nil // Don't consider source code locations essential.
	}

	// Model each YAML document as a resource
	resources := map[k8s_Key]models.ResourceState{}
	errors := []error{}
	for documentIdx, document := range documents {
		if !k8s_hasRequiredFields(document) {
			errors = append(
				errors,
				fmt.Errorf("%w: invalid Kubernetes document at index %d", InvalidInput, documentIdx),
			)
		} else {
			key, err := k8s_parseKey(document)
			if err != nil {
				return nil, err
			}

			sources[key] = documentSources[documentIdx]
			resources[key] = models.ResourceState{
				Id:           key.name,
				Namespace:    key.namespace,
				ResourceType: key.kind,
				Meta:         map[string]interface{}{},
				Attributes:   document,
			}
		}
	}

	if len(resources) == 0 {
		return nil, fmt.Errorf("%w: did not contain any valid YAML documents", InvalidInput)
	}

	return &k8s_Configuration{
		path:      i.Path,
		resources: resources,
		sources:   sources,
		errors:    errors,
	}, nil
}

func (c *KubernetesDetector) DetectDirectory(i *Directory, opts DetectOptions) (IACConfiguration, error) {
	return nil, nil
}

type k8s_Configuration struct {
	path      string
	resources map[k8s_Key]models.ResourceState
	sources   map[k8s_Key]SourceInfoNode
	errors    []error
}

func (l *k8s_Configuration) ToState() models.State {
	resourcesByType := map[string]map[string]models.ResourceState{}
	for _, resource := range l.resources {
		if _, ok := resourcesByType[resource.ResourceType]; !ok {
			resourcesByType[resource.ResourceType] = map[string]models.ResourceState{}
		}

		key := fmt.Sprintf("%s.%s", resource.Namespace, resource.Id)
		resourcesByType[resource.ResourceType][key] = resource
	}

	return models.State{
		InputType:           Kubernetes.Name,
		EnvironmentProvider: "iac",
		Meta: map[string]interface{}{
			"filepath": l.path,
		},
		Resources: resourcesByType,
		Scope: map[string]interface{}{
			"filepath": l.path,
		},
	}
}

func (l *k8s_Configuration) Location(path []interface{}) (LocationStack, error) {
	// Format is {resourceNamespace, resourceType, resourceId, attributePath...}
	if l.sources == nil || len(path) < 3 {
		return nil, nil
	}

	resourceNamespace, ok := path[0].(string)
	if !ok {
		return nil, fmt.Errorf(
			"%w: Expected string resource namespace in path: %v",
			UnableToResolveLocation,
			path,
		)
	}

	resourceType, ok := path[1].(string)
	if !ok {
		return nil, fmt.Errorf(
			"%w: Expected string resource type in path: %v",
			UnableToResolveLocation,
			path,
		)
	}

	resourceId, ok := path[2].(string)
	if !ok {
		return nil, fmt.Errorf(
			"%w: Expected string resource ID in path: %v",
			UnableToResolveLocation,
			path,
		)
	}

	key := k8s_Key{namespace: resourceNamespace, kind: resourceType, name: resourceId}
	if source, ok := l.sources[key]; ok {
		node, err := source.GetPath(path[3:])
		line, column := node.Location()
		return []Location{{Path: l.path, Line: line, Col: column}}, err
	} else {
		return nil, nil
	}
}

func (l *k8s_Configuration) LoadedFiles() []string {
	return []string{l.path}
}

func (l *k8s_Configuration) Errors() []error {
	return l.errors
}

func (l *k8s_Configuration) Type() *Type {
	return Kubernetes
}

func splitYAML(data []byte) ([]map[string]interface{}, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var documents []map[string]interface{}
	for {
		var value map[string]interface{}
		err := dec.Decode(&value)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		documents = append(documents, value)
	}
	return documents, nil
}

func k8s_hasRequiredFields(doc map[string]interface{}) bool {
	required := []string{"apiVersion", "kind"}
	for _, k := range required {
		if _, ok := doc[k]; !ok {
			return false
		}
	}
	return true
}

func k8s_parseKey(document map[string]interface{}) (k8s_Key, error) {
	key := k8s_Key{}
	if kind, ok := document["kind"].(string); ok {
		key.kind = kind
	} else {
		return key, fmt.Errorf("%w: input file does not define a kind", InvalidInput)
	}
	if metadata, ok := document["metadata"].(map[string]interface{}); ok {
		key.name, _ = metadata["name"].(string)
		key.namespace, _ = metadata["namespace"].(string)
	}
	if key.name == "" {
		return key, fmt.Errorf("%w: input file does not define a name", InvalidInput)
	}
	if key.namespace == "" {
		key.namespace = "default"
	}
	return key, nil
}

type k8s_Key struct {
	kind      string
	namespace string
	name      string
}
