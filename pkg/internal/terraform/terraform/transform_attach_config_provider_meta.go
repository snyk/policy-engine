package terraform

import (
	"github.com/snyk/policy-engine/pkg/internal/terraform/addrs"
	"github.com/snyk/policy-engine/pkg/internal/terraform/configs"
)

// GraphNodeAttachProviderMetaConfigs is an interface that must be implemented
// by nodes that want provider meta configurations attached.
type GraphNodeAttachProviderMetaConfigs interface {
	GraphNodeConfigResource

	// Sets the configuration
	AttachProviderMetaConfigs(map[addrs.Provider]*configs.ProviderMeta)
}
