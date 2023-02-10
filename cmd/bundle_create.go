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
