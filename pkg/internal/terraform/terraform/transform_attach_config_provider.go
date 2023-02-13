package terraform

import (
	"github.com/snyk/policy-engine/pkg/internal/terraform/addrs"
	"github.com/snyk/policy-engine/pkg/internal/terraform/configs"
)

// GraphNodeAttachProvider is an interface that must be implemented by nodes
// that want provider configurations attached.
type GraphNodeAttachProvider interface {
	// ProviderName with no module prefix. Example: "aws".
	ProviderAddr() addrs.AbsProviderConfig

	// Sets the configuration
	AttachProvider(*configs.Provider)
}
