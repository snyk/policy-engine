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

package input

import (
	"context"
	"errors"
	"fmt"

	"github.com/snyk/policy-engine/pkg/input/cloudapi"
	"github.com/snyk/policy-engine/pkg/models"
)

type CloudClient interface {
	Resources(ctx context.Context, orgID string, params cloudapi.ResourcesParameters) ([]cloudapi.ResourceObject, error)
}

type CloudLoader struct {
	Client CloudClient
}

var ErrFailedToFetchCloudState = errors.New("failed to fetch cloud state")

func (l *CloudLoader) GetState(ctx context.Context, orgID string, params cloudapi.ResourcesParameters) (*models.State, error) {
	cloudResources, err := l.Client.Resources(ctx, orgID, params)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedToFetchCloudState, err)
	}
	resources := map[string]map[string]models.ResourceState{}
	for _, r := range cloudResources {
		attrs := r.Attributes
		if _, ok := resources[attrs.ResourceType]; !ok {
			resources[attrs.ResourceType] = map[string]models.ResourceState{}
		}
		resources[attrs.ResourceType][attrs.ResourceID] = convertAPIResource(attrs)
	}
	return &models.State{
		InputType:           CloudScan.Name,
		EnvironmentProvider: "cloud",
		Scope:               cloudScope(orgID, params),
		Resources:           resources,
	}, nil
}

func cloudScope(orgID string, params cloudapi.ResourcesParameters) map[string]interface{} {
	scope := map[string]interface{}{
		"org_id": orgID,
	}
	if len(params.EnvironmentID) > 0 {
		scope["environment_id"] = params.EnvironmentID
	}
	if len(params.ResourceType) > 0 {
		scope["resource_type"] = params.ResourceType
	}
	if len(params.ResourceID) > 0 {
		scope["resource_id"] = params.ResourceID
	}
	if len(params.NativeID) > 0 {
		scope["native_id"] = params.NativeID
	}
	if len(params.ID) > 0 {
		scope["id"] = params.ID
	}
	if len(params.Platform) > 0 {
		scope["platform"] = params.Platform
	}
	if len(params.Name) > 0 {
		scope["name"] = params.Name
	}
	if len(params.Location) > 0 {
		scope["location"] = params.Location
	}
	return scope
}

func convertAPIResource(r cloudapi.ResourceAttributes) models.ResourceState {
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
	return resource
}
