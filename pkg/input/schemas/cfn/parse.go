// Copyright 2022-2023 Snyk Ltd
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

package cfn

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io/ioutil"
	"strings"

	"github.com/snyk/policy-engine/pkg/input/schemas"
)

type schema struct {
	TypeName    string              `json:"typeName"`
	Properties  map[string]property `json:"properties"`
	Definitions map[string]property `json:"definitions"`
}

type property struct {
	Ref        string              `json:"$ref"`
	Type       interface{}         `json:"type"` // String or array of string
	Properties map[string]property `json:"properties"`
	Items      *property           `json:"items"`
}

func (p property) isRef() bool {
	return p.Ref != ""
}

func (p property) getRef() string {
	return strings.TrimPrefix(p.Ref, "#/definitions/")
}

func (p property) getType() (schemas.Type, bool) {
	if str, ok := p.Type.(string); ok {
		switch str {
		case "boolean":
			return schemas.Bool, true
		case "integer":
			return schemas.Int, true
		case "number":
			return schemas.Float, true
		case "string":
			return schemas.String, true
		case "array":
			return schemas.Array, true
		case "object":
			return schemas.Object, true
		}
	}
	return schemas.Object, false
}

// Conversion of schemas as they are in CloudformationSchema.zip to the above
// type.
func (schema schema) convert() *schemas.Schema {
	// Declare definitions first so they can be reused.
	definitions := map[string]*schemas.Schema{}
	for key := range schema.Definitions {
		definitions[key] = &schemas.Schema{}
	}

	// Property conversion resolves references in `Definitions`.
	var convertProperty func(property) *schemas.Schema
	convertProperty = func(prop property) *schemas.Schema {
		if prop.isRef() {
			if def, ok := definitions[prop.getRef()]; ok {
				return def
			} else {
				return nil
			}
		} else {
			out := schemas.Schema{}
			if ty, ok := prop.getType(); ok {
				out.Type = ty
			} else {
				return nil
			}
			if len(prop.Properties) > 0 {
				out.Properties = map[string]*schemas.Schema{}
				for k, v := range prop.Properties {
					out.Properties[k] = convertProperty(v)
				}
			}
			if prop.Items != nil {
				out.Items = convertProperty(*prop.Items)
			}
			return &out
		}
	}

	// Convert definitions.
	for k, def := range definitions {
		if out := convertProperty(schema.Definitions[k]); out != nil {
			def.Type = out.Type
			def.Properties = out.Properties
			def.Items = out.Items
		}
	}

	// Convert properties.
	properties := map[string]*schemas.Schema{}
	for key, prop := range schema.Properties {
		properties[key] = convertProperty(prop)
	}

	// Return schema.
	return &schemas.Schema{
		Type:       schemas.Object,
		Properties: properties,
	}
}

func parseSchemasFromZip(zipbytes []byte) ([]schema, error) {
	schemas := []schema{}
	r, err := zip.NewReader(bytes.NewReader(zipbytes), int64(len(zipbytes)))
	if err != nil {
		return nil, err
	}

	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}

		body, err := ioutil.ReadAll(rc)
		if err != nil {
			return nil, err
		}
		rc.Close()

		var schema schema
		err = json.Unmarshal(body, &schema)
		if err != nil {
			return nil, err
		}

		schemas = append(schemas, schema)
	}

	return schemas, nil
}
