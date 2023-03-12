package input

import (
	"context"
	"os"

	"github.com/snyk/policy-engine/pkg/input/cloudapi"
	"github.com/snyk/policy-engine/pkg/models"
)

type CloudLoader struct {
	client *cloudapi.Client
}

func NewCloudLoader() (*CloudLoader, error) {
	client, err := cloudapi.NewClient(cloudapi.ClientConfig{
		URL:     os.Getenv("SNYK_API"),
		Token:   os.Getenv("SNYK_TOKEN"),
		Version: os.Getenv("API_VERSION"),
	})
	if err != nil {
		return nil, err
	}

	return &CloudLoader{client: client}, nil
}

func (l *CloudLoader) GetState(ctx context.Context, orgID string, params cloudapi.ResourcesParameters) ([]models.State, error) {
	resources, err := l.client.Resources(ctx, orgID, params)
	if err != nil {
		return nil, err
	}
	resourceAttributes := make([]cloudapi.ResourceAttributes, len(resources))
	for idx, r := range resources {
		resourceAttributes[idx] = r.Attributes
	}
	config := cloudScanConfiguration{
		resources: resourceAttributes,
	}
	return []models.State{config.ToState()}, nil
}
