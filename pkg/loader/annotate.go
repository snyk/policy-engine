package loader

import (
	"github.com/snyk/unified-policy-engine/pkg/models"
)

// TODO: create a map[[3]string]FilePath map.  Then lookup resources here and
// check if they have a filepath.  The filepath comes from meta.  Then we can
// look up resources by their [3]string and retrieve resource location info if
// available.

// Annotate a report with source location information
func Annotate(
	configurations LoadedConfigurations,
	results *models.Results,
) {
	for _, inputResult := range results.Results {
		for rid, resources := range inputResult.Input.Resources {
			for _, resource := range resources {
				location := annotateResourceLocation(
					configurations,
					resource.Namespace,
					resource.Id,
					resource.ResourceType,
				)
				if resource.Meta == nil {
					resource.Meta = map[string]interface{}{}
				}
				if len(location) > 0 {
					resource.Meta["location"] = location
				}
				resources[rid] = resource
			}
		}

		for _, ruleResult := range inputResult.RuleResults {
			for _, result := range ruleResult.Results {
				for _, resource := range result.Resources {
					location := annotateResourceLocation(
						configurations,
						resource.Namespace,
						resource.Id,
						resource.Type,
					)
					resource.Location = location

					for i := range resource.Attributes {
						attributePath := []interface{}{resource.Type, resource.Id}
						attributePath = append(attributePath, resource.Attributes[i].Path...)
						location, _ := configurations.Location(resource.Namespace, attributePath)
						if len(location) > 0 {
							loc := toLocation(location[0])
							resource.Attributes[i].Location = &loc
						}
					}
				}
			}
		}
	}
}

func annotateResourceLocation(
	configurations LoadedConfigurations,
	resourceNamespace string,
	resourceId string,
	resourceType string,
) []models.SourceLocation {
	resourcePath := []interface{}{resourceType, resourceId}
	resourceLocs, _ := configurations.Location(resourceNamespace, resourcePath)
	if resourceLocs == nil {
		return nil
	}
	locations := []models.SourceLocation{}
	for _, loc := range resourceLocs {
		locations = append(locations, toLocation(loc))
	}
	return locations
}

func toLocation(loc Location) models.SourceLocation {
	return models.SourceLocation{
		Filepath: loc.Path,
		Line:     loc.Line,
		Column:   loc.Col,
	}
}
