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

package tf

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"io/ioutil"

	"github.com/snyk/policy-engine/pkg/input/schemas"
)

//go:embed aws.json.gz
var awsJsonGz []byte

//go:embed azurerm.json.gz
var azurermJsonGz []byte

//go:embed google.json.gz
var googleJsonGz []byte

var allSchemaFiles [][]byte = [][]byte{
	awsJsonGz,
	azurermJsonGz,
	googleJsonGz,
}

var loadedSchemas map[string]*schemas.Schema = map[string]*schemas.Schema{}

func loadSchema(schemaFile []byte) error {
	reader, err := gzip.NewReader(bytes.NewReader(schemaFile))
	if err != nil {
		return err
	}

	bytes, err := ioutil.ReadAll(reader)
	if err != nil {
		return err
	}

	var schemas map[string]*schemas.Schema
	if err := json.Unmarshal(bytes, &schemas); err != nil {
		return err
	}

	for k, schema := range schemas {
		loadedSchemas[k] = schema
	}

	return nil
}

func loadSchemas() error {
	for _, schemaFile := range allSchemaFiles {
		if err := loadSchema(schemaFile); err != nil {
			return nil
		}
	}
	return nil
}

func GetSchema(resourceType string) *schemas.Schema {
	if len(loadedSchemas) == 0 {
		if err := loadSchemas(); err != nil {
			panic(err)
		}
	}

	if schema, ok := loadedSchemas[resourceType]; ok {
		return schema
	} else {
		return nil
	}
}
