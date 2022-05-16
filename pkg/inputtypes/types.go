package inputtypes

import (
	"fmt"
	"strings"
)

type InputType struct {
	Name     string
	Aliases  []string
	Children InputTypes
}

func (t *InputType) Matches(inputType string) bool {
	if t.Name == inputType {
		return true
	}
	for _, c := range t.Children {
		if c.Matches(inputType) {
			return true
		}
	}
	return false
}

func (t *InputType) FuzzyMatches(inputType string) bool {
	inputType = strings.ToLower(inputType)
	if t.Name == inputType {
		return true
	}
	for _, a := range t.Aliases {
		if a == inputType {
			return true
		}
	}
	for _, c := range t.Children {
		if c.FuzzyMatches(inputType) {
			return true
		}
	}
	return false
}

type InputTypes []*InputType

func (t InputTypes) FromString(inputType string) (*InputType, error) {
	inputType = strings.ToLower(inputType)
	for _, i := range t {
		if i.Name == inputType {
			return i, nil
		}
		for _, a := range i.Aliases {
			if a == inputType {
				return i, nil
			}
		}
	}
	return nil, fmt.Errorf("Unrecognized input type")
}

var Arm = &InputType{
	Name: "arm",
}
var CloudFormation = &InputType{
	Name:    "cfn",
	Aliases: []string{"cloudformation"},
}
var CloudScan = &InputType{
	Name:    "cloud_scan",
	Aliases: []string{"cloud-scan"},
}
var Kubernetes = &InputType{
	Name:    "k8s",
	Aliases: []string{"kubernetes"},
}
var TerraformHCL = &InputType{
	Name:    "tf_hcl",
	Aliases: []string{"tf-hcl"},
}
var TerraformPlan = &InputType{
	Name:    "tf_plan",
	Aliases: []string{"tf-plan"},
}
var Terraform = &InputType{
	Name:    "tf",
	Aliases: []string{"terraform"},
	Children: InputTypes{
		TerraformHCL,
		TerraformPlan,
		CloudScan,
	},
}
