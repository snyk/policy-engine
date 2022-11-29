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

package embed

import (
	_ "embed"
)

//go:embed snyk.rego
var SnykRego []byte

//go:embed snyk/terraform.rego
var snykTerraformRego []byte

//go:embed snyk/relations.rego
var snykRelationsRego []byte

//go:embed snyk/internal/relations.rego
var snykInternalRelationsRego []byte

var SnykLib map[string][]byte = map[string][]byte{
	"snyk/terraform.rego":          snykTerraformRego,
	"snyk/relations.rego":          snykRelationsRego,
	"snyk/internal/relations.rego": snykInternalRelationsRego,
}
