// © 2022-2023 Snyk Limited All rights reserved.
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

package arm

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var resourceTypePattern = regexp.MustCompile(`^Microsoft\.\w+[/\w]*$`)

// https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-functions-resource#resourceid
func resourceIDImpl(e *EvaluationContext, args ...interface{}) (interface{}, error) {
	strargs, err := assertAllType[string](args...)
	if err != nil {
		return nil, err
	}
	fqResourceID, err := extractSubscriptionAndResourceGroupIDs(strargs)
	if err != nil {
		return nil, err
	}
	resourceID, err := mergeResourceTypesAndNames(fqResourceID.resourceType, fqResourceID.resourceNames)
	if err != nil {
		return nil, err
	}

	// Normalize resource IDs to declared/discovered ones in the input, so that
	// these can be associated with each other by policy queries.
	if _, ok := e.DiscoveredResourceSet[resourceID]; ok {
		return resourceID, nil
	}

	fullyQualifiedID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/%s", fqResourceID.subscriptionID, fqResourceID.resourceGroupName, resourceID)
	return fullyQualifiedID, nil
}

type fullyQualifiedResourceID struct {
	subscriptionID    string
	resourceGroupName string
	resourceType      string
	resourceNames     []string
}

func extractSubscriptionAndResourceGroupIDs(args []string) (fullyQualifiedResourceID, error) {
	// Fall back on these stubs, extract parameters below if passed
	subscriptionID := "stub-subscription-id"
	resourceGroupName := "stub-resource-group-name"
	var resourceTypeAndNames []string

	foundResourceType := false
	for i, arg := range args {
		if resourceTypePattern.MatchString(arg) {
			foundResourceType = true

			// If the resource type was not the first arg, we can extract
			// resourceGroupID and possibly also subscriptionID from the front of the
			// args
			switch i {
			case 0:
				resourceTypeAndNames = args[:]
				//nolint:gosimple
				break
			case 1:
				resourceGroupName = args[0]
				resourceTypeAndNames = args[1:]
				//nolint:gosimple
				break
			case 2:
				subscriptionID = args[0]
				resourceGroupName = args[1]
				resourceTypeAndNames = args[2:]
				//nolint:gosimple
				break
			default:
				return fullyQualifiedResourceID{}, fmt.Errorf("resourceId: expected to find resource type at argument index 0 or 1, found at %d", i)
			}
		}
	}
	if !foundResourceType {
		return fullyQualifiedResourceID{}, errors.New("resourceId: found no argument that resembles a resource type")
	}
	if len(resourceTypeAndNames) < 2 {
		return fullyQualifiedResourceID{}, errors.New("resourceId: expected at least a resource type and single resource name to be specified")
	}
	return fullyQualifiedResourceID{
		subscriptionID:    subscriptionID,
		resourceGroupName: resourceGroupName,
		resourceType:      resourceTypeAndNames[0],
		resourceNames:     resourceTypeAndNames[1:],
	}, nil
}

// Create Azure-style resource address:
// (Microsoft.Namespace/Type1/Type2, name1, name2) => Microsoft.Namespace/Type1/name1/Type2/name2
func mergeResourceTypesAndNames(resourceType string, resourceNames []string) (string, error) {
	resourceTypeParts := strings.Split(resourceType, "/")
	if len(resourceTypeParts) < 2 {
		return "", fmt.Errorf("resourceId: expected at least 2 slash-separated components of resourceType %s", resourceType)
	}
	resourceNamespace := resourceTypeParts[0]
	resourceTypes := resourceTypeParts[1:]
	if len(resourceTypes) != len(resourceNames) {
		return "", fmt.Errorf("resourceId: mismatched number of resource types (%d) and names (%d) specified", len(resourceTypes), len(resourceNames))
	}

	resourceID := ""
	for i, resourceType := range resourceTypes {
		resourceName := resourceNames[i]
		resourceID += fmt.Sprintf("/%s/%s", resourceType, resourceName)
	}
	return resourceNamespace + resourceID, nil
}
