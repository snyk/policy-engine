// © 2022-2023 Snyk Limited All rights reserved.
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
var snykRego []byte

//go:embed snyk/internal/relations_cache.rego
var snykRelationsCache []byte

//go:embed snyk/terraform.rego
var snykTerraformRego []byte

//go:embed snyk/relations.rego
var snykRelationsRego []byte

//go:embed snyk/internal/relations.rego
var snykInternalRelationsRego []byte

var SnykBuiltins map[string][]byte = map[string][]byte{
	"snyk.rego":                          snykRego,
	"snyk/internal/relations_cache.rego": snykRelationsCache,
}

var SnykLib map[string][]byte = map[string][]byte{
	"snyk/terraform.rego":          snykTerraformRego,
	"snyk/relations.rego":          snykRelationsRego,
	"snyk/internal/relations.rego": snykInternalRelationsRego,
}
