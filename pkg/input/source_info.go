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

// This file contains some utilities to deal with extracting source code
// information from generic JSON / YAML files.

package input

import (
	"bytes"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

type SourceInfoNode struct {
	key  *yaml.Node // Possibly nil
	body *yaml.Node
}

type SourceInfoOptions struct {
	// Some formats may try to access an array using a string.  This corresponds
	// to selecting an item in the array, which has a given field (e.g. "key"
	// or "name") set to this value.  This option allows you to set these fields
	// if applicable.  They are tried in the order you specify them.
	ArrayKeyFields []string
}

func LoadSourceInfoNode(contents []byte) (*SourceInfoNode, error) {
	multi, err := LoadMultiSourceInfoNode(contents)
	if err != nil {
		return nil, err
	}
	return &multi[0], nil
}

// LoadMultiSourceInfoNode parses YAML documents with multiple entries, or
// normal single YAML/JSON documents.
func LoadMultiSourceInfoNode(contents []byte) ([]SourceInfoNode, error) {
	dec := yaml.NewDecoder(bytes.NewReader(contents))
	var documents []*yaml.Node
	for {
		value := yaml.Node{}
		err := dec.Decode(&value)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if value.Kind == yaml.DocumentNode {
			for _, doc := range value.Content {
				documents = append(documents, doc)
			}
		} else {
			documents = append(documents, &value)
		}
	}

	if len(documents) < 1 {
		return nil, fmt.Errorf("No document contents")
	}

	nodes := []SourceInfoNode{}
	for _, doc := range documents {
		nodes = append(nodes, SourceInfoNode{body: doc})
	}
	return nodes, nil
}

func (node *SourceInfoNode) getKey(key string) (*SourceInfoNode, error) {
	if node.body.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("Expected %s but got %s", prettyKind(yaml.MappingNode), prettyKind(node.body.Kind))
	}

	for i := 0; i+1 < len(node.body.Content); i += 2 {
		if node.body.Content[i].Value == key {
			return &SourceInfoNode{key: node.body.Content[i], body: node.body.Content[i+1]}, nil
		}
	}

	return nil, fmt.Errorf("Key %s not found", key)
}

func (node *SourceInfoNode) getIndex(index int) (*SourceInfoNode, error) {
	if node.body.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("Expected %s but got %s", prettyKind(yaml.SequenceNode), prettyKind(node.body.Kind))
	}

	if index < 0 || index >= len(node.body.Content) {
		return nil, fmt.Errorf("Index %d out of bounds for length %d", index, len(node.body.Content))
	}

	return &SourceInfoNode{body: node.body.Content[index]}, nil
}

func (node *SourceInfoNode) getArrayKeyField(arrayKeyFields []string, index string) (*SourceInfoNode, error) {
	if node.body.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("Expected %s but got %s", prettyKind(yaml.SequenceNode), prettyKind(node.body.Kind))
	}

	for _, key := range arrayKeyFields {
		for _, child := range node.body.Content {
			if child.Kind == yaml.MappingNode {
				for i := 0; i+1 < len(child.Content); i += 2 {
					if child.Content[i].Value == key {
						if child.Content[i+1].Value == index {
							return &SourceInfoNode{body: child.Content[i+1]}, nil
						}
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("Key %s not found", index)
}

// GetPath tries to retrieve a path as far as possible.
func (node *SourceInfoNode) GetPathWithOptions(
	options SourceInfoOptions,
	path []interface{},
) (*SourceInfoNode, error) {
	if len(path) == 0 {
		return node, nil
	}

	switch node.body.Kind {
	case yaml.MappingNode:
		key, ok := path[0].(string)
		if !ok {
			return node, fmt.Errorf("Expected string key")
		}
		child, err := node.getKey(key)
		if err != nil {
			return node, err
		} else {
			return child.GetPathWithOptions(options, path[1:])
		}
	case yaml.SequenceNode:
		index, ok := path[0].(int)
		if !ok {
			index, ok := path[0].(string)
			if ok && len(options.ArrayKeyFields) > 0 {
				child, err := node.getArrayKeyField(options.ArrayKeyFields, index)
				if err != nil {
					return node, err
				} else {
					return child.GetPathWithOptions(options, path[1:])
				}
			}

			return node, fmt.Errorf("Expected int index")
		}

		child, err := node.getIndex(index)
		if err != nil {
			return node, err
		} else {
			return child.GetPathWithOptions(options, path[1:])
		}
	default:
		return node, fmt.Errorf("Expected %s or %s at key %s but got %s", prettyKind(yaml.MappingNode), prettyKind(yaml.SequenceNode), path[0], prettyKind(node.body.Kind))
	}
}

// GetPath tries to retrieve a path as far as possible.
func (node *SourceInfoNode) GetPath(path []interface{}) (*SourceInfoNode, error) {
	return node.GetPathWithOptions(SourceInfoOptions{}, path)
}

func (node *SourceInfoNode) Location() (int, int) {
	if node.key != nil {
		return node.key.Line, node.key.Column
	} else {
		return node.body.Line, node.body.Column
	}
}

func prettyKind(kind yaml.Kind) string {
	switch kind {
	case yaml.MappingNode:
		return "map"
	case yaml.SequenceNode:
		return "array"
	case yaml.DocumentNode:
		return "doc"
	case yaml.AliasNode:
		return "alias"
	case yaml.ScalarNode:
		return "scalar"
	default:
		return "unknown"
	}
}
