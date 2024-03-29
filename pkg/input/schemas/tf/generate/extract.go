// © 2023 Snyk Limited All rights reserved.
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

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func Extract() error {
	provider, err := ShimProvider()
	if err != nil {
		return err
	}

	schema := map[string]*Schema{}
	for resourceType, resource := range provider.ResourcesMap {
		fmt.Fprintf(os.Stderr, "Extracting resource type: %s\n", resourceType)
		schema[resourceType] = ExtractResource(resource)
	}

	bytes, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return err
	}

	_, err = os.Stdout.Write(bytes)
	return err
}

func ExtractResource(resource *schema.Resource) *Schema {
	schema := Schema{
		Type:       Object,
		Properties: map[string]*Schema{},
	}
	for k, prop := range resource.Schema {
		if s := ExtractSchema(prop); s != nil {
			schema.Properties[k] = s
		}
	}
	return &schema
}

func ExtractSchema(original *schema.Schema) *Schema {
	schema := Schema{Type: ExtractType(original.Type)}
	schema.Sensitive = original.Sensitive
	switch schema.Type {
	case Unknown:
		return nil
	case Array:
		schema.Items = ExtractElem(original.Elem)
	case Map:
		schema.Items = ExtractElem(original.Elem)
	case Object:
		return ExtractElem(original.Elem)
	}
	return &schema
}

func ExtractElem(elem interface{}) *Schema {
	switch v := elem.(type) {
	case *schema.Schema:
		return ExtractSchema(v)
	case *schema.Resource:
		return ExtractResource(v)
	default:
		return nil
	}
}

func ExtractType(ty schema.ValueType) Type {
	switch ty {
	case schema.TypeBool:
		return Bool
	case schema.TypeInt:
		return Int
	case schema.TypeFloat:
		return Float
	case schema.TypeString:
		return String
	case schema.TypeList:
		return Array
	case schema.TypeMap:
		return Map
	case schema.TypeSet:
		return Array
	default:
		return Unknown
	}
}

func main() {
	if err := Extract(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
