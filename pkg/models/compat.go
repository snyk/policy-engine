package models

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Compatibility type to unmarshal controls in the old (map-based) as well
// as the new (array-based) format.
func ParseControls(data interface{}) ([]string, error) {
	controls := []string{}
	if familyMap, ok := data.(map[string]interface{}); ok {
		families := []string{}
		for family := range familyMap {
			families = append(families, family)
		}
		sort.Strings(families)
		for _, family := range families {
			if versionMap, ok := familyMap[family].(map[string]interface{}); ok {
				versions := []string{}
				for version := range versionMap {
					versions = append(versions, version)
				}
				sort.Strings(versions)
				for _, version := range versions {
					if sections, ok := versionMap[version].([]interface{}); ok {
						for _, section := range sections {
							if section, ok := section.(string); ok {
								control := fmt.Sprintf("%s_%s_%s", family, version, section)
								controls = append(controls, control)
							} else {
								return nil, fmt.Errorf("controls section should be string")
							}
						}
					} else {
						return nil, fmt.Errorf("controls version should contain array")
					}
				}
			} else {
				return nil, fmt.Errorf("controls family should contain object")
			}
		}
	} else if controlSlice, ok := data.([]interface{}); ok {
		for _, control := range controlSlice {
			if control := control.(string); ok {
				controls = append(controls, control)
			} else {
				return nil, fmt.Errorf("control should be string")
			}
		}
	} else if data != nil {
		return nil, fmt.Errorf("controls should contain array or object")
	}
	return controls, nil
}

func (r *RuleResults) UnmarshalJSON(data []byte) error {
	compat := struct {
		Id            string                 `json:"id,omitempty"`
		Title         string                 `json:"title,omitempty"`
		Platform      []string               `json:"platform,omitempty"`
		Description   string                 `json:"description,omitempty"`
		References    []RuleResultsReference `json:"references,omitempty"`
		Category      string                 `json:"category,omitempty"`
		Labels        []string               `json:"labels,omitempty"`
		ServiceGroup  string                 `json:"service_group,omitempty"`
		Controls      interface{}            `json:"controls"`
		ResourceTypes []string               `json:"resource_types,omitempty"`
		Results       []RuleResult           `json:"results"`
		Errors        []string               `json:"errors,omitempty"`
		Package_      string                 `json:"package,omitempty"`
		Kind          string                 `json:"kind,omitempty"`
		RuleBundle    *RuleBundle            `json:"rule_bundle,omitempty"`
	}{}
	err := json.Unmarshal(data, &compat)
	if err != nil {
		return err
	}
	r.Id = compat.Id
	r.Title = compat.Title
	r.Platform = compat.Platform
	r.Description = compat.Description
	r.References = compat.References
	r.Category = compat.Category
	r.Labels = compat.Labels
	r.ServiceGroup = compat.ServiceGroup
	if r.Controls, err = ParseControls(compat.Controls); err != nil {
		return err
	}
	r.ResourceTypes = compat.ResourceTypes
	r.Results = compat.Results
	r.Errors = compat.Errors
	r.Package_ = compat.Package_
	r.Kind = compat.Kind
	r.RuleBundle = compat.RuleBundle
	return nil
}
