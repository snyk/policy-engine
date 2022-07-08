package cfn_schemas

import (
	_ "embed"
)

//go:embed CloudformationSchema.zip
var cloudformationSchemaZip []byte

var cloudformationSchemas map[string]schema = nil

// Called the first time a schema is requested.
func loadCloudformationSchemas() {
	if cloudformationSchemas != nil {
		return
	}

	cloudformationSchemas = map[string]schema{}
	schemas, err := parseSchemasFromZip(cloudformationSchemaZip)
	if err != nil {
		panic(err)
	}

	for _, schema := range schemas {
		cloudformationSchemas[schema.TypeName] = schema
	}
}

func GetSchema(resourceType string) *Schema {
	loadCloudformationSchemas()
	if schema, ok := cloudformationSchemas[resourceType]; ok {
		return schema.convert()
	} else {
		return unknownSchema
	}
}
