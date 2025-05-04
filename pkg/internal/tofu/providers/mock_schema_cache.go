package providers

import "github.com/snyk/policy-engine/pkg/internal/tofu/addrs"

func NewMockSchemaCache() *schemaCache {
	return &schemaCache{
		m: make(map[addrs.Provider]ProviderSchema),
	}
}
