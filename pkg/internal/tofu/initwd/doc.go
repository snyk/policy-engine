// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package initwd contains various helper functions used by the "tofu init"
// command to initialize a working directory.
//
// These functions may also be used from testing code to simulate the behaviors
// of "tofu init" against test fixtures, but should not be used elsewhere
// in the main code.
package initwd
