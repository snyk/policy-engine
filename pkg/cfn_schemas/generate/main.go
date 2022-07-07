package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"text/template"
)

type Schema struct {
	TypeName    string               `json:"typeName"`
	Properties  map[string]*Property `json:"properties"`
	Definitions map[string]*Property `json:"definitions"`
}

func (s *Schema) SetSchema() {
	for _, p := range s.Properties {
		p.SetSchema(s)
	}
	for _, d := range s.Definitions {
		d.SetSchema(s)
	}
}

type Property struct {
	Ref        string               `json:"$ref"`
	Type       interface{}          `json:"type"` // String or array of string
	Properties map[string]*Property `json:"properties"`
	Items      *Property            `json:"items"`

	Schema *Schema // Set using SetSchema
}

func (p *Property) SetSchema(schema *Schema) {
	p.Schema = schema
	for _, child := range p.Properties {
		child.SetSchema(schema)
	}
	if p.Items != nil {
		p.Items.SetSchema(schema)
	}
}

func (p *Property) IsRef() bool {
	return p.Ref != ""
}

func (p *Property) GetRef() string {
	return strings.TrimPrefix(p.Ref, "#/definitions/")
}

func (p *Property) isType(ty string) bool {
	if str, ok := p.Type.(string); ok && str == ty {
		return true
	}
	return false
}

func (p *Property) IsBoolean() bool {
	return p.isType("boolean")
}

func (p *Property) IsInteger() bool {
	return p.isType("integer")
}

func (p *Property) IsNumber() bool {
	return p.isType("number")
}

func (p *Property) IsString() bool {
	return p.isType("string")
}

func (p *Property) IsArray() bool {
	return p.isType("array")
}

func (p *Property) IsObject() bool {
	return p.isType("object")
}

func ReadSchemasFromZip(path string) (map[string]*Schema, error) {
	schemas := map[string]*Schema{}

	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

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

		var schema Schema
		err = json.Unmarshal(body, &schema)
		if err != nil {
			return nil, err
		}

		schemas[schema.TypeName] = &schema
	}

	return schemas, nil
}

func main() {
	schemas, err := ReadSchemasFromZip("generate/CloudformationSchema.zip")
	check(err)
	fmt.Fprintf(os.Stderr, "Found %d schemas\n", len(schemas))

	for _, schema := range schemas {
		schema.SetSchema()
	}

	f, err := os.Create("schemas.go")
	check(err)
	defer f.Close()

	tmpl, err := template.ParseFiles("generate/schemas.gotempl")
	check(err)
	err = tmpl.Execute(f, schemas)
	check(err)
}

func check(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
