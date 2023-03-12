package input

import (
	"github.com/snyk/policy-engine/pkg/input/cloudapi"
	"github.com/snyk/policy-engine/pkg/models"
)

type cloudScanConfiguration struct {
	resources []cloudapi.ResourceAttributes
}

func (c *cloudScanConfiguration) ToState() models.State {
	resources := make([]models.ResourceState, len(c.resources))
	for idx, r := range c.resources {
		resource := models.ResourceState{
			Id:           r.ResourceID,
			ResourceType: r.ResourceType,
			Namespace:    r.Namespace,
			Attributes:   r.State,
		}
		if len(r.Tags) > 0 {
			// We don't support non-string tags in policy-engine atm. Maybe
			// we'll change this at some point.
			tags := map[string]string{}
			for k, v := range r.Tags {
				if s, ok := v.(string); ok {
					tags[k] = s
				}
			}
			resource.Tags = tags
		}
		resources[idx] = resource
	}

	// TODO: we should populate meta and scope here based on the resources.
	return models.State{
		InputType:           CloudScan.Name,
		EnvironmentProvider: "cloud",
		Resources:           groupResourcesByType(resources),
	}
}

func (c *cloudScanConfiguration) LoadedFiles() []string {
	return nil
}

func (c *cloudScanConfiguration) Location(attributePath []interface{}) (LocationStack, error) {
	return nil, nil
}

func (c *cloudScanConfiguration) Errors() []error {
	return nil
}

func (c *cloudScanConfiguration) Type() *Type {
	return CloudScan
}
