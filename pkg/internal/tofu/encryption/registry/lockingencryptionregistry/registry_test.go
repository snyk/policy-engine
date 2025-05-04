// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package lockingencryptionregistry_test

import (
	"testing"

	"github.com/snyk/policy-engine/pkg/internal/tofu/encryption/registry/compliancetest"
	"github.com/snyk/policy-engine/pkg/internal/tofu/encryption/registry/lockingencryptionregistry"
)

func TestCompliance(t *testing.T) {
	compliancetest.ComplianceTest(t, lockingencryptionregistry.New)
}
