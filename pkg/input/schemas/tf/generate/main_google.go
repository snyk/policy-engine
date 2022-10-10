package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-google/google"
)

func ShimProvider() (*schema.Provider, error) {
	return google.Provider(), nil
}
