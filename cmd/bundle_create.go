package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/snyk/policy-engine/pkg/bundle"
	v1 "github.com/snyk/policy-engine/pkg/bundle/v1"
	"github.com/spf13/cobra"
)

var (
	bundleCreateOutput   string
	bundleCreateRevision string
	bundleCreateVCSType  string
	bundleCreateVCSURI   string
)

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
		if bundleCreateRevision != "" {
			opts = append(opts, v1.WithRevision(bundleCreateRevision))
		}
		if bundleCreateVCSType != "" {
			opts = append(opts, v1.WithVCSType(bundleCreateVCSType))
		}
		if bundleCreateVCSURI != "" {
			opts = append(opts, v1.WithVCSURI(bundleCreateVCSURI))
		}
		b, err := bundle.BuildBundle(reader, opts...)
		if err != nil {
			return err
		}
		f, err := os.Create(bundleCreateOutput)
		if err != nil {
			return err
		}
		writer := bundle.NewTarGzWriter(f)
		if err := writer.Write(b); err != nil {
			return err
		}
		logger.
			WithField("output", bundleCreateOutput).
			Info(ctx, "wrote bundle")
		return nil
	},
}

func init() {
	bundleCreateCmd.Flags().StringVarP(&bundleCreateOutput, "output", "o", "dist.tar.gz", ".tar.gz file to write to")
	bundleCreateCmd.Flags().StringVarP(&bundleCreateRevision, "revision", "r", "", "the revision of this bundle, e.g. a commit hash")
	bundleCreateCmd.Flags().StringVarP(&bundleCreateVCSType, "vcs-type", "t", "", "the vcs type of this bundle, e.g. 'git'")
	bundleCreateCmd.Flags().StringVarP(&bundleCreateVCSURI, "vcs-uri", "u", "", "the vcs repo URI of this bundle, e.g. 'git@github.com:example/rules.git")
}
