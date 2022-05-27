package embed

import (
	_ "embed"
)

//go:embed snyk.rego
var SnykRego []byte

//go:embed snyk/terraform.rego
var SnykTerraformRego []byte
