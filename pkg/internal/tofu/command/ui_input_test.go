// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/tofu"
)

func TestUIInput_impl(t *testing.T) {
	var _ tofu.UIInput = new(UIInput)
}

func TestUIInputInput(t *testing.T) {
	i := &UIInput{
		Reader: bytes.NewBufferString("foo\n"),
		Writer: bytes.NewBuffer(nil),
	}

	v, err := i.Input(context.Background(), &tofu.InputOpts{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if v != "foo" {
		t.Fatalf("unexpected input: %s", v)
	}
}

func TestUIInputInput_canceled(t *testing.T) {
	r, w := io.Pipe()
	i := &UIInput{
		Reader: r,
		Writer: bytes.NewBuffer(nil),
	}

	// Make a context that can be canceled.
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		// Cancel the context after 2 seconds.
		time.Sleep(2 * time.Second)
		cancel()
	}()

	// Get input until the context is canceled.
	v, err := i.Input(ctx, &tofu.InputOpts{})
	if err != context.Canceled {
		t.Fatalf("expected a context.Canceled error, got: %v", err)
	}

	// As the context was canceled v should be empty.
	if v != "" {
		t.Fatalf("unexpected input: %s", v)
	}

	// As the context was canceled we should still be listening.
	listening := atomic.LoadInt32(&i.listening)
	if listening != 1 {
		t.Fatalf("expected listening to be 1, got: %d", listening)
	}

	go func() {
		// Fake input is given after 1 second.
		time.Sleep(time.Second)
		fmt.Fprint(w, "foo\n")
		w.Close()
	}()

	v, err = i.Input(context.Background(), &tofu.InputOpts{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if v != "foo" {
		t.Fatalf("unexpected input: %s", v)
	}
}

func TestUIInputInput_spaces(t *testing.T) {
	i := &UIInput{
		Reader: bytes.NewBufferString("foo bar\n"),
		Writer: bytes.NewBuffer(nil),
	}

	v, err := i.Input(context.Background(), &tofu.InputOpts{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if v != "foo bar" {
		t.Fatalf("unexpected input: %s", v)
	}
}

func TestUIInputInput_Error(t *testing.T) {
	i := &UIInput{
		Reader: bytes.NewBuffer(nil),
		Writer: bytes.NewBuffer(nil),
	}

	v, err := i.Input(context.Background(), &tofu.InputOpts{})
	if err == nil {
		t.Fatalf("Error is not 'nil'")
	}

	if err.Error() != "EOF" {
		t.Fatalf("unexpected error: %v", err)
	}

	if v != "" {
		t.Fatalf("input must be empty")
	}
}
