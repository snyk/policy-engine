package terraform

import "github.com/snyk/policy-engine/pkg/internal/terraform/tfdiags"

// GraphNodeExecutable is the interface that graph nodes must implement to
// enable execution.
type GraphNodeExecutable interface {
	Execute(EvalContext, walkOperation) tfdiags.Diagnostics
}
