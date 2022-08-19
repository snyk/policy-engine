package legacyiac

import (
	"sort"
	"strings"

	"github.com/snyk/policy-engine/pkg/models"
)

type K8sInput struct {
	resourceNamespace string
	resourceType      string
	resourceId        string
	document          map[string]interface{}
}

func NewK8sInputs(state *models.State) []Input {
	inputs := []Input{}

	// Need to be deterministic for tests.
	resourceTypes := []string{}
	for resourceType := range state.Resources {
		resourceTypes = append(resourceTypes, resourceType)
	}
	sort.Strings(resourceTypes)

	for _, resourceType := range resourceTypes {
		resources := state.Resources[resourceType]

		// Need to be deterministic for tests.
		resourceKeys := []string{}
		for key := range resources {
			resourceKeys = append(resourceKeys, key)
		}
		sort.Strings(resourceKeys)

		for _, k := range resourceKeys {
			r := resources[k]
			input := K8sInput{
				resourceNamespace: r.Namespace,
				resourceType:      r.ResourceType,
				resourceId:        r.Id,
				document:          r.Attributes,
			}
			inputs = append(inputs, &input)
		}

	}

	return inputs
}

func (k *K8sInput) Raw() interface{} {
	return k.document
}

func (k *K8sInput) ParseMsg(msg string) ParsedMsg {
	path := parsePath(msg)

	// Some paths may start with "kind.", remove that part.
	if len(path) > 0 {
		if resourceType, ok := path[0].(string); ok &&
			strings.ToLower(resourceType) == strings.ToLower(k.resourceType) {
			path = path[1:]
		}
	}

	return ParsedMsg{
		ResourceID:        k.resourceId,
		ResourceType:      k.resourceType,
		ResourceNamespace: k.resourceNamespace,
		Path:              path,
	}
}
