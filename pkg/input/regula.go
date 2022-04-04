// This file contains regula compatibility for UPE.  It is bit messy since we
// need to parse things back.  Ideally we would kill this and produce the input
// directly.
package input

import (
    "fmt"

	"github.com/fugue/regula/v2/pkg/loader"
)

func parseRegulaResource(r map[string]interface{}) (*Resource, error) {
	id, ok := r["id"].(string)
	if !ok {
		return nil, fmt.Errorf("Missing id on resource")
	}

	type_, ok := r["_type"].(string)
	if !ok {
		return nil, fmt.Errorf("Missing _type on resource")
	}

	return &Resource{
		Id:    id,
		Type:  type_,
		Value: r,
	}, nil
}

func parseRegulaResources(rs map[string]interface{}) (ResourcesByType, error) {
	rbt := ResourcesByType{}
	for k, r := range rs {
		if rmap, ok := r.(map[string]interface{}); ok {
			resource, err := parseRegulaResource(rmap)
			if err != nil {
				return nil, err
			}

			if _, ok := rbt[resource.Type]; !ok {
				rbt[resource.Type] = map[string]*Resource{}
			}

			rbt[resource.Type][k] = resource
		}
	}
	return rbt, nil
}

func parseRegulaInput(r loader.RegulaInput) (*Input, error) {
	if filepath, ok := r["filepath"].(string); ok {
		if contents, ok := r["content"].(map[string]interface{}); ok {
			if resources, ok := contents["resources"].(map[string]interface{}); ok {
				rbt, err := parseRegulaResources(resources)
				if err != nil {
					return nil, err
				}

				return &Input{
					Path:      filepath,
					Resources: rbt,
				}, nil
			}
		}

	}

	return nil, fmt.Errorf("Missing filepath/contents")
}

func LoadRegulaInputs(paths []string) ([]*Input, error) {
	configLoader := loader.LocalConfigurationLoader(loader.LoadPathsOptions{
		Paths:       paths,
		InputTypes:  []loader.InputType{loader.Auto},
		NoGitIgnore: false,
		IgnoreDirs:  false,
	})

	loadedConfigs, err := configLoader()
	if err != nil {
		return nil, err
	}

	inputs := []*Input{}
	for _, r := range loadedConfigs.RegulaInput() {
		input, err := parseRegulaInput(r)
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, input)
	}
	return inputs, nil
}
