// Package regoversion holds the Rego syntax version used to parse and compile
// policies. Rules are still authored in Rego v0 syntax; changing Default to
// ast.RegoV1 is the switch for moving policies to Rego v1.
package regoversion

import "github.com/open-policy-agent/opa/v1/ast"

const Default = ast.RegoV0

func ParserOptions() ast.ParserOptions {
	return ast.ParserOptions{RegoVersion: Default}
}
