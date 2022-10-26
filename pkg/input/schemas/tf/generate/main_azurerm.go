package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-azurerm/internal/provider"
)

func ShimProvider() (*schema.Provider, error) {
	return provider.AzureProvider(), nil
}
