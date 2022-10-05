package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/terraform-providers/terraform-provider-aws/aws"
)

func generate(outPath string) error {
	provider, ok := aws.Provider().(*schema.Provider)
	if !ok {
		return fmt.Errorf("Failed to cast provider to schema.Provider")
	}

	schema := map[string]*Schema{}
	for resourceType, resource := range provider.ResourcesMap {
		fmt.Fprintf(os.Stderr, "Processing resource type: %s\n", resourceType)
		schema[resourceType] = ProcessResource(resource)
	}

	bytes, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(outPath, bytes, 0644)
}

type Type = string

const (
	TypeUnknown Type = "unknown"
	TypeBool    Type = "bool"
	TypeInt     Type = "int"
	TypeFloat   Type = "float"
	TypeString  Type = "string"
	TypeList    Type = "list"
	TypeSet     Type = "set"
	TypeMap     Type = "map"
	TypeObject  Type = "object"
)

type Schema struct {
	Type       Type               `json:"type"`
	Sensitive  bool               `json:"sensitive,omitempty"`
	Properties map[string]*Schema `json:"properties,omitempty"`
	Elem       *Schema            `json:"elem,omitempty"`
}

func ProcessResource(resource *schema.Resource) *Schema {
	schema := Schema{
		Type:       TypeObject,
		Properties: map[string]*Schema{},
	}
	for k, prop := range resource.Schema {
		if s := ProcessSchema(prop); s != nil {
			schema.Properties[k] = s
		}
	}
	return &schema
}

func ProcessSchema(original *schema.Schema) *Schema {
	schema := Schema{Type: ProcessType(original.Type)}
	schema.Sensitive = original.Sensitive
	switch schema.Type {
	case TypeUnknown:
		return nil
	case TypeList:
		schema.Elem = ProcessElem(original.Elem)
	case TypeSet:
		schema.Elem = ProcessElem(original.Elem)
	case TypeMap:
		schema.Elem = ProcessElem(original.Elem)
	case TypeObject:
		return ProcessElem(original.Elem)
	}
	return &schema
}

func ProcessElem(elem interface{}) *Schema {
	switch v := elem.(type) {
	case *schema.Schema:
		return ProcessSchema(v)
	case *schema.Resource:
		return ProcessResource(v)
	default:
		return nil
	}
}

func ProcessType(ty schema.ValueType) Type {
	switch ty {
	case schema.TypeBool:
		return TypeBool
	case schema.TypeInt:
		return TypeInt
	case schema.TypeFloat:
		return TypeFloat
	case schema.TypeString:
		return TypeString
	case schema.TypeList:
		return TypeList
	case schema.TypeMap:
		return TypeMap
	case schema.TypeSet:
		return TypeSet
	default:
		return TypeUnknown
	}
}

func main() {
	if err := generate("aws.json"); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
