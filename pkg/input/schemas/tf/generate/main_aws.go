package main

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-aws/internal/provider"
)

func ShimProvider() (*schema.Provider, error) {
	ctx := context.Background()
	return provider.New(ctx)
}
