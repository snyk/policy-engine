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
	".yaml": true,
	".yml":  true,
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
	if len(documents) == 0 {
		return nil, fmt.Errorf("%w: did not contain any valid YAML documents", InvalidInput)
	}

	// Model each YAML document as a resource
	resources := map[string]interface{}{}
	content := map[string]interface{}{
		"k8s_resource_view_version": "0.0.1",
		"resources":                 resources,
	}

	sources := map[string]SourceInfoNode{}
	documentSources, err := LoadMultiSourceInfoNode(contents)
	if err != nil {
		documentSources = nil // Don't consider source code locations essential.
	}

	for documentIdx, document := range documents {
		var name, namespace string
		kind, ok := document["kind"]
		if !ok {
			return nil, fmt.Errorf("%w: input file does not define a kind", InvalidInput)
		}
		if metadata, ok := document["metadata"].(map[string]interface{}); ok {
			name, _ = metadata["name"].(string)
			namespace, _ = metadata["namespace"].(string)
		}
		if name == "" {
			return nil, fmt.Errorf("%w: input file does not define a name", InvalidInput)
		}
		if namespace == "" {
			namespace = "default"
		}

		resourceId := fmt.Sprintf("%s.%s.%s", kind, namespace, name)
		resources[resourceId] = document
		sources[resourceId] = documentSources[documentIdx]
	}

	return &k8sConfiguration{
		path:      i.Path,
		content:   content,
		sources:   sources,
		resources: resources,
	}, nil
}

func (c *KubernetesDetector) DetectDirectory(i *Directory, opts DetectOptions) (IACConfiguration, error) {
	return nil, nil
}

type k8sConfiguration struct {
	path      string
	content   map[string]interface{}
	sources   map[string]SourceInfoNode
	resources map[string]interface{}
}

func (l *k8sConfiguration) ToState() models.State {
	return toState(Kubernetes.Name, l.path, l.resources)
}

func (l *k8sConfiguration) Location(path []interface{}) (LocationStack, error) {
	return nil, nil
	/* TODO: Location() is not yet supported for k8s.

	if len(path) < 1 {
		return nil, nil
	}

	resourceId := path[0]
	if resource, ok := l.sources[resourceId]; ok {
		line, column := resource.Location()
		return []Location{{Path: l.path, Line: line, Col: column}}, nil
	} else {
		return nil, nil
	}
	*/
}

func (l *k8sConfiguration) LoadedFiles() []string {
	return []string{l.path}
}

func (l *k8sConfiguration) Errors() []error {
	return []error{}
}
