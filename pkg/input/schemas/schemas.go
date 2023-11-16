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

package schemas

import (
	"fmt"
	"strconv"
	"strings"
)

type Type string

const (
	Unknown Type = "unknown"
	Bool    Type = "bool"
	Int     Type = "int"
	Float   Type = "float"
	String  Type = "string"
	Array   Type = "array"
	Map     Type = "map"
	Object  Type = "object"
)

// A Schema correponds to a resource or a subtree of a resource.
// They may contain infinite loops.
type Schema struct {
	Type       Type               `json:"type"`
	Sensitive  bool               `json:"sensitive,omitempty"`
	Properties map[string]*Schema `json:"properties,omitempty"`
	Items      *Schema            `json:"items,omitempty"`
}

func Apply(val interface{}, schema *Schema) interface{} {
	if schema == nil {
		return val
	}

	if schema.Sensitive {
		switch v := val.(type) {
		case string:
			// In some terraform plans, unset attributes are represented by the empty
			// string rather than null. If we mask this, we lose distinction between
			// set and unset attributes which can cause false positives or negatives
			// in policies.
			if v == "" {
				return ""
			}

			return "******"
		default:
			return nil
		}
	}

	switch v := val.(type) {
	case []interface{}:
		return ApplyArray(v, schema)
	case map[string]interface{}:
		return ApplyObject(v, schema)
	case string:
		switch schema.Type {
		case String:
			return v
		case Bool:
			return strings.ToLower(v) == "true"
		case Int:
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
		case Float:
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				return f
			}
		}
	case int:
		switch schema.Type {
		case String:
			return fmt.Sprintf("%d", v)
		}
	case float64:
		switch schema.Type {
		case String:
			return fmt.Sprintf("%f", v)
		}
	}

	return val
}

func ApplyArray(arr []interface{}, schema *Schema) []interface{} {
	if schema == nil || schema.Type != Array || schema.Items == nil {
		return arr
	}

	if schema.Sensitive {
		return nil
	}

	coerce := make([]interface{}, len(arr))
	for i, v := range arr {
		coerce[i] = Apply(v, schema.Items)
	}
	return coerce
}

func ApplyObject(obj map[string]interface{}, schema *Schema) map[string]interface{} {
	if schema == nil {
		return obj
	}

	if schema.Sensitive {
		return nil
	}

	coerce := map[string]interface{}{}
	if schema.Type == Object {
		for k, v := range obj {
			if s, ok := schema.Properties[k]; ok {
				coerce[k] = Apply(v, s)
			} else {
				coerce[k] = v
			}
		}
		return coerce
	} else if schema.Type == Map {
		for k, v := range obj {
			coerce[k] = Apply(v, schema.Items)
		}
		return coerce
	}
	return obj
}
