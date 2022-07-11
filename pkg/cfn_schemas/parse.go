package cfn_schemas

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io/ioutil"
	"strings"
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

func (p property) getType() Type {
	if str, ok := p.Type.(string); ok {
		switch str {
		case "boolean":
			return Boolean
		case "integer":
			return Integer
		case "number":
			return Number
		case "string":
			return String
		case "array":
			return Array
		case "object":
			return Object
		}
	}
	return Unknown
}

// We only need one.
var unknownSchema = &Schema{Type: Unknown}

// Conversion of schemas as they are in CloudformationSchema.zip to the above
// type.
func (schema schema) convert() *Schema {
	// Declare definitions first so they can be reused.
	definitions := map[string]*Schema{}
	for key := range schema.Definitions {
		definitions[key] = &Schema{}
	}

	// Property conversion resolves references in `Definitions`.
	var convertProperty func(property) *Schema
	convertProperty = func(prop property) *Schema {
		if prop.isRef() {
			if def, ok := definitions[prop.getRef()]; ok {
				return def
			} else {
				return unknownSchema
			}
		} else {
			out := Schema{
				Type:       prop.getType(),
				Properties: nil,
				Items:      nil,
			}
			if len(prop.Properties) > 0 {
				out.Properties = map[string]*Schema{}
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
		out := convertProperty(schema.Definitions[k])
		def.Type = out.Type
		def.Properties = out.Properties
		def.Items = out.Items
	}

	// Convert properties.
	properties := map[string]*Schema{}
	for key, prop := range schema.Properties {
		properties[key] = convertProperty(prop)
	}

	// Return schema.
	return &Schema{
		Type:       Object,
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