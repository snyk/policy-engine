package embed

import (
	_ "embed"
)

//go:embed snyk.rego
var SnykRego []byte
