package cmd

import (
	"context"

	"github.com/snyk/policy-engine/pkg/input"
	"github.com/snyk/policy-engine/pkg/input/cloudapi"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/spf13/cobra"
)

type cloudOptions struct {
	OrgID         string
	EnvIDs        []string
	ResourceTypes []string
	ResourceIDs   []string
	NativeIDs     []string
	IDs           []string
	Platforms     []string
	Names         []string
	Locations     []string
}

func (c *cloudOptions) addFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&c.OrgID, "cloud.org", "", "Cloud organization ID (required to fetch cloud resources)")
	cmd.PersistentFlags().StringSliceVar(&c.EnvIDs, "cloud.env", nil, "Cloud environment IDs (optional, can be specified multiple times)")
	cmd.PersistentFlags().StringSliceVar(&c.ResourceTypes, "cloud.resource-type", nil, "Cloud resource types (optional, can be specified multiple times)")
	cmd.PersistentFlags().StringSliceVar(&c.ResourceIDs, "cloud.resource-id", nil, "Cloud resource IDs (optional, can be specified multiple times)")
	cmd.PersistentFlags().StringSliceVar(&c.NativeIDs, "cloud.native-id", nil, "Cloud resource native IDs, e.g. AWS resource ARNs (optional, can be specified multiple times)")
	cmd.PersistentFlags().StringSliceVar(&c.IDs, "cloud.id", nil, "Cloud resource UUIDs (optional, can be specified multiple times)")
	cmd.PersistentFlags().StringSliceVar(&c.Platforms, "cloud.platform", nil, "Cloud platforms, e.g. aws, azure (optional, can be specified multiple times)")
	cmd.PersistentFlags().StringSliceVar(&c.Names, "cloud.name", nil, "Cloud resource names (optional, can be specified multiple times)")
	cmd.PersistentFlags().StringSliceVar(&c.Locations, "cloud.location", nil, "Cloud resource locations, e.g. us-east-1 (optional, can be specified multiple times)")
}

func (c *cloudOptions) enabled() bool {
	return c.OrgID != ""
}

func getCloudStates(ctx context.Context, options cloudOptions) ([]models.State, error) {
	cloudLoader, err := input.NewCloudLoader()
	if err != nil {
		return nil, err
	}
	return cloudLoader.GetState(ctx, options.OrgID, cloudapi.ResourcesParameters{
		EnvironmentID: options.EnvIDs,
		ResourceType:  options.ResourceTypes,
		ResourceID:    options.ResourceIDs,
		NativeID:      options.NativeIDs,
		ID:            options.IDs,
		Platform:      options.Platforms,
		Name:          options.Names,
		Location:      options.Locations,
	})
}
