// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package depsfile contains the logic for reading and writing OpenTofu's
// dependency lock and development override configuration files.
//
// These files are separate from the main OpenTofu configuration files (.tf)
// for a number of reasons. The first is to help establish a distinction
// where .tf files configure a particular module while these configure
// a whole configuration tree. Another, more practical consideration is that
// we intend both of these files to be primarily maintained automatically by
// OpenTofu itself, rather than by human-originated edits, and so keeping
// them separate means that it's easier to distinguish the files that OpenTofu
// will change automatically during normal workflow from the files that
// OpenTofu only edits on direct request.
//
// Both files use HCL syntax, for consistency with other files in OpenTofu
// that we expect humans to (in this case, only occasionally) edit directly.
// A dependency lock file tracks the most recently selected upstream versions
// of each dependency, and is intended for checkin to version control.
// A development override file allows for temporarily overriding upstream
// dependencies with local files/directories on disk as an aid to testing
// a cross-codebase change during development, and should not be saved in
// version control.
package depsfile
