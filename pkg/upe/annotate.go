package upe

import (
	"github.com/snyk/unified-policy-engine/pkg/loader"
	"github.com/snyk/unified-policy-engine/pkg/models"
)

// Annotate a report with source location information
func Annotate(
	results *models.Results,
	configurations loader.LoadedConfigurations,
) {
	for _, inputResult := range results.Results {
		for rid, resources := range inputResult.Input.Resources {
			for _, resource := range resources {
				location := resourceLocation(
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
					location := resourceLocation(
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

func resourceLocation(
	configurations loader.LoadedConfigurations,
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

func toLocation(loc loader.Location) models.SourceLocation {
	return models.SourceLocation{
		Filepath: loc.Path,
		Line:     loc.Line,
		Column:   loc.Col,
	}
}
