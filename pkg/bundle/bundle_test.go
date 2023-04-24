// © 2023 Snyk Limited All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bundle_test

import (
	"embed"
	"io/fs"
	"testing"

	"github.com/snyk/policy-engine/pkg/bundle"
	"github.com/snyk/policy-engine/pkg/bundle/base"
	v1 "github.com/snyk/policy-engine/pkg/bundle/v1"
	"github.com/stretchr/testify/assert"
)

//go:embed v1/test_inputs/complete
var completeBundleV1 embed.FS

//go:embed v1/test_inputs/minimal
var minimalBundleV1 embed.FS

func TestReadBundle(t *testing.T) {
	testCases := []struct {
		name        string
		root        string
		fsys        fs.FS
		manifest    v1.Manifest
		sourceInfo  base.SourceInfo
		filesLoaded []string
		err         error
	}{
		{
			name: "minimal bundle",
			root: "v1/test_inputs/minimal",
			fsys: minimalBundleV1,
			manifest: v1.Manifest{
				Manifest: base.Manifest{
					BundleFormatVersion: v1.VERSION,
				},
			},
			sourceInfo: base.SourceInfo{
				SourceType: bundle.DIRECTORY,
				FileInfo: base.FileInfo{
					Path: "v1/test_inputs/minimal",
				},
			},
			filesLoaded: []string{
				"rules/some_rule.rego",
			},
		},
		{
			name: "complete bundle",
			root: "v1/test_inputs/complete",
			fsys: completeBundleV1,
			manifest: v1.Manifest{
				Manifest: base.Manifest{
					BundleFormatVersion: v1.VERSION,
				},
				Name:                "acme_complete_bundle",
				PolicyEngineVersion: "v0.15.0",
				Revision:            "924d418a9f8f05a66c7dab87989fad631abc291d",
				VCS: v1.VCSMetadata{
					Type: "git",
					URI:  "git@github.com:example/rules.git",
				},
			},
			sourceInfo: base.SourceInfo{
				SourceType: bundle.DIRECTORY,
				FileInfo: base.FileInfo{
					Path: "v1/test_inputs/complete",
				},
			},
			filesLoaded: []string{
				"lib/utils.rego",
				"rules/EXAMPLE_01/terraform.rego",
				"rules/EXAMPLE_02/terraform.rego",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reader := bundle.NewFSReader(tc.root, tc.fsys)
			b, err := bundle.ReadBundle(reader)
			if tc.err != nil {
				assert.NoError(t, err)
				assert.ErrorIs(t, tc.err, err)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, tc.manifest, b.Manifest())
				assert.Equal(t, tc.sourceInfo, b.SourceInfo())
				assert.Equal(t, v1.VERSION, b.BundleFormatVersion())
				modules := b.Modules()
				for _, f := range tc.filesLoaded {
					assert.Contains(t, modules, f)
				}
			}
		})
	}
}
