// Copyright 2023 Snyk Ltd
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

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/snyk/policy-engine/pkg/bundle"
	v1 "github.com/snyk/policy-engine/pkg/bundle/v1"
	"github.com/spf13/cobra"
)

var bundleCreateFlags struct {
	Output   string
	Revision string
	VCSType  string
	VCSURI   string
}

var bundleCreateCmd = &cobra.Command{
	Use:   "create <bundle directory> [-o <output .tar.gz file>]",
	Short: "Create a bundle from a local directory",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		logger := cmdLogger()
		if len(args) != 1 {
			return fmt.Errorf("exactly one directory must be specified")
		}
		reader := bundle.NewDirReader(args[0])
		opts := []v1.ManifestOption{}
		if bundleCreateFlags.Revision != "" {
			opts = append(opts, v1.WithRevision(bundleCreateFlags.Revision))
		}
		if bundleCreateFlags.VCSType != "" {
			opts = append(opts, v1.WithVCSType(bundleCreateFlags.VCSType))
		}
		if bundleCreateFlags.VCSURI != "" {
			opts = append(opts, v1.WithVCSURI(bundleCreateFlags.VCSURI))
		}
		b, err := bundle.BuildBundle(reader, opts...)
		if err != nil {
			return err
		}
		f, err := os.Create(bundleCreateFlags.Output)
		if err != nil {
			return err
		}
		writer := bundle.NewTarGzWriter(f)
		if err := writer.Write(b); err != nil {
			return err
		}
		logger.
			WithField("output", bundleCreateFlags.Output).
			Info(ctx, "wrote bundle")
		return nil
	},
}

func init() {
	bundleCreateCmd.Flags().StringVarP(&bundleCreateFlags.Output, "output", "o", "dist.tar.gz", ".tar.gz file to write to")
	bundleCreateCmd.Flags().StringVarP(&bundleCreateFlags.Revision, "revision", "r", "", "the revision of this bundle, e.g. a commit hash")
	bundleCreateCmd.Flags().StringVarP(&bundleCreateFlags.VCSType, "vcs-type", "t", "", "the vcs type of this bundle, e.g. 'git'")
	bundleCreateCmd.Flags().StringVarP(&bundleCreateFlags.VCSURI, "vcs-uri", "u", "", "the vcs repo URI of this bundle, e.g. 'git@github.com:example/rules.git")
}
