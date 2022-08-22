// Copyright 2022 Snyk Ltd
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
	_ "embed"
)

type Type int

const (
	Boolean Type = iota
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
		return nil
	}
}

// The file CloudformationSchema.zip can be downloaded here:
// <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-type-schemas.html>
//
// There are little differences from region to region, but none that really
// impact the property coercion we want to do.  We chose the us-east-2 zip
// since that region has many features.

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
