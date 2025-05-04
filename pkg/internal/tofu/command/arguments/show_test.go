// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package arguments

import (
	"reflect"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func TestParseShow_valid(t *testing.T) {
	testCases := map[string]struct {
		args []string
		want *Show
	}{
		"defaults": {
			nil,
			&Show{
				Path:     "",
				ViewType: ViewHuman,
			},
		},
		"json": {
			[]string{"-json"},
			&Show{
				Path:     "",
				ViewType: ViewJSON,
			},
		},
		"path": {
			[]string{"-json", "foo"},
			&Show{
				Path:     "foo",
				ViewType: ViewJSON,
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			got, diags := ParseShow(tc.args)
			got.Vars = nil
			if len(diags) > 0 {
				t.Fatalf("unexpected diags: %v", diags)
			}
			if *got != *tc.want {
				t.Fatalf("unexpected result\n got: %#v\nwant: %#v", got, tc.want)
			}
		})
	}
}

func TestParseShow_invalid(t *testing.T) {
	testCases := map[string]struct {
		args      []string
		want      *Show
		wantDiags tfdiags.Diagnostics
	}{
		"unknown flag": {
			[]string{"-boop"},
			&Show{
				Path:     "",
				ViewType: ViewHuman,
			},
			tfdiags.Diagnostics{
				tfdiags.Sourceless(
					tfdiags.Error,
					"Failed to parse command-line flags",
					"flag provided but not defined: -boop",
				),
			},
		},
		"too many arguments": {
			[]string{"-json", "bar", "baz"},
			&Show{
				Path:     "bar",
				ViewType: ViewJSON,
			},
			tfdiags.Diagnostics{
				tfdiags.Sourceless(
					tfdiags.Error,
					"Too many command line arguments",
					"Expected at most one positional argument.",
				),
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			got, gotDiags := ParseShow(tc.args)
			got.Vars = nil
			if *got != *tc.want {
				t.Fatalf("unexpected result\n got: %#v\nwant: %#v", got, tc.want)
			}
			if !reflect.DeepEqual(gotDiags, tc.wantDiags) {
				t.Errorf("wrong result\ngot: %s\nwant: %s", spew.Sdump(gotDiags), spew.Sdump(tc.wantDiags))
			}
		})
	}
}
