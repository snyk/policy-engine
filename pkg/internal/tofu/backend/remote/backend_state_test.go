// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package remote

import (
	"bytes"
	"testing"

	"github.com/snyk/policy-engine/pkg/internal/tofu/backend"
	"github.com/snyk/policy-engine/pkg/internal/tofu/cloud"
	"github.com/snyk/policy-engine/pkg/internal/tofu/encryption"
	"github.com/snyk/policy-engine/pkg/internal/tofu/states"
	"github.com/snyk/policy-engine/pkg/internal/tofu/states/remote"
	"github.com/snyk/policy-engine/pkg/internal/tofu/states/statefile"
)

func TestRemoteClient_impl(t *testing.T) {
	var _ remote.Client = new(remoteClient)
}

func TestRemoteClient(t *testing.T) {
	client := testRemoteClient(t)
	remote.TestClient(t, client)
}

func TestRemoteClient_stateLock(t *testing.T) {
	b, bCleanup := testBackendDefault(t)
	defer bCleanup()

	s1, err := b.StateMgr(backend.DefaultStateName)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	s2, err := b.StateMgr(backend.DefaultStateName)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	remote.TestRemoteLocks(t, s1.(*remote.State).Client, s2.(*remote.State).Client)
}

func TestRemoteClient_Put_withRunID(t *testing.T) {
	// Set the TFE_RUN_ID environment variable before creating the client!
	t.Setenv("TFE_RUN_ID", cloud.GenerateID("run-"))

	// Create a new test client.
	client := testRemoteClient(t)

	// Create a new empty state.
	sf := statefile.New(states.NewState(), "", 0)
	var buf bytes.Buffer
	statefile.Write(sf, &buf, encryption.StateEncryptionDisabled())

	// Store the new state to verify (this will be done
	// by the mock that is used) that the run ID is set.
	if err := client.Put(buf.Bytes()); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}
