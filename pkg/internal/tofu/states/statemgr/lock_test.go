// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package statemgr

import (
	"testing"
)

func TestLockDisabled_impl(t *testing.T) {
	var _ Full = new(LockDisabled)
	var _ Locker = new(LockDisabled)
}
