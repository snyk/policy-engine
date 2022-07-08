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

func (p property) IsRef() bool {
	return p.Ref != ""
}

func (p property) GetRef() string {
	return strings.TrimPrefix(p.Ref, "#/definitions/")
}

func (p property) GetType() Type {
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
