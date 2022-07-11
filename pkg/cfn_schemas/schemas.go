package cfn_schemas

import (
	_ "embed"
)

type Type int

const (
	Unknown Type = iota
	Boolean
	Integer
	Number
	String
	Array
	Object
)

// A Schema correponds to a resource or a subtree of a resource.
// They may contain infinite loops.
type Schema struct {
	Type       Type
	Properties map[string]*Schema
	Items      *Schema
}

func ResourceTypes() []string {
	loadCloudformationSchemas()
	resourceTypes := []string{}
	for k := range cloudformationSchemas {
		resourceTypes = append(resourceTypes, k)
	}
	return resourceTypes
}

func GetSchema(resourceType string) *Schema {
	loadCloudformationSchemas()
	if schema, ok := cloudformationSchemas[resourceType]; ok {
		return schema
	} else {
		return unknownSchema
	}
}

//go:embed CloudformationSchema.zip
var cloudformationSchemaZip []byte

var cloudformationSchemas map[string]*Schema = nil

// Loads schemas into loadCloudformationSchemas if necessary.
func loadCloudformationSchemas() {
	if cloudformationSchemas != nil {
		return
	}

	cloudformationSchemas = map[string]*Schema{}
	schemas, err := parseSchemasFromZip(cloudformationSchemaZip)
	if err != nil {
		panic(err)
	}

	for _, schema := range schemas {
		cloudformationSchemas[schema.TypeName] = schema.convert()
	}
}
