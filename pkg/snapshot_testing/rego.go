package snapshot_testing

import (
	"context"

	"github.com/open-policy-agent/opa/ast"
	"github.com/snyk/policy-engine/pkg/data"
)

// NoopProvider gives a pure rego implementation of the snapshot_testing
// package.  This version will always return true, and should be used everywhere
// except for actual testing.
var NoopProvider data.Provider = func(ctx context.Context, consumer data.Consumer) error {
	module := ast.MustParseModule(`
package snapshot_testing

match(_, _) {
    true
}
`)
	return consumer.Module(ctx, "snapshot_testing.rego", module)
}
