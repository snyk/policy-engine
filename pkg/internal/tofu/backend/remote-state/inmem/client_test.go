// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package inmem

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/snyk/policy-engine/pkg/internal/tofu/backend"
	"github.com/snyk/policy-engine/pkg/internal/tofu/encryption"
	"github.com/snyk/policy-engine/pkg/internal/tofu/states/remote"
)

func TestRemoteClient_impl(t *testing.T) {
	var _ remote.Client = new(RemoteClient)
	var _ remote.ClientLocker = new(RemoteClient)
}

func TestRemoteClient(t *testing.T) {
	defer Reset()
	b := backend.TestBackendConfig(t, New(encryption.StateEncryptionDisabled()), hcl.EmptyBody())

	s, err := b.StateMgr(backend.DefaultStateName)
	if err != nil {
		t.Fatal(err)
	}

	remote.TestClient(t, s.(*remote.State).Client)
}

func TestInmemLocks(t *testing.T) {
	defer Reset()
	s, err := backend.TestBackendConfig(t, New(encryption.StateEncryptionDisabled()), hcl.EmptyBody()).StateMgr(backend.DefaultStateName)
	if err != nil {
		t.Fatal(err)
	}

	remote.TestRemoteLocks(t, s.(*remote.State).Client, s.(*remote.State).Client)
}
