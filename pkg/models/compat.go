package models

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Compatibility type to unmarshal controls in the old (map-based) as well
// as the new (array-based) format.
type ControlsParser struct {
	Controls []string
}

func (r *ControlsParser) UnmarshalJSON(data []byte) error {
	old := map[string]map[string][]string{}
	controls := []string{}
	if err := json.Unmarshal(data, &old); err == nil {
		families := []string{}
		for family := range old {
			families = append(families, family)
		}
		sort.Strings(families)
		for _, family := range families {
			versions := []string{}
			for version := range old[family] {
				versions = append(versions, version)
			}
			sort.Strings(versions)
			for _, version := range versions {
				for _, section := range old[family][version] {
					control := fmt.Sprintf("%s_%s_%s", family, version, section)
					controls = append(controls, control)
				}
			}
		}
		r.Controls = controls
		return nil
	} else {
		if err := json.Unmarshal(data, &controls); err != nil {
			return err
		} else {
			r.Controls = controls
			return nil
		}
	}
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
		Controls      ControlsParser         `json:"controls"`
		ResourceTypes []string               `json:"resource_types,omitempty"`
		Results       []RuleResult           `json:"results"`
		Errors        []string               `json:"errors,omitempty"`
		Package_      string                 `json:"package,omitempty"`
	}{}
	if err := json.Unmarshal(data, &compat); err != nil {
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
	r.Controls = compat.Controls.Controls
	r.ResourceTypes = compat.ResourceTypes
	r.Results = compat.Results
	r.Errors = compat.Errors
	r.Package_ = compat.Package_
	return nil
}
