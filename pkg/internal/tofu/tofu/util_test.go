// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tofu

import (
	"testing"
	"time"
)

func TestSemaphore(t *testing.T) {
	s := NewSemaphore(2)
	timer := time.AfterFunc(time.Second, func() {
		panic("deadlock")
	})
	defer timer.Stop()

	s.Acquire()
	if !s.TryAcquire() {
		t.Fatalf("should acquire")
	}
	if s.TryAcquire() {
		t.Fatalf("should not acquire")
	}
	s.Release()
	s.Release()

	// This release should panic
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("should panic")
		}
	}()
	s.Release()
}
