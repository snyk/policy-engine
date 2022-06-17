package inputs

import (
	"fmt"
	"strings"
)

// InputType represents one or more types of inputs.
type InputType struct {
	// Name is the primary name for this input type. This is the field to use when input
	// types need to be serialized to a string.
	Name string
	// Aliases are alternate, case-insensitive names for this input type.
	Aliases []string
	// Children are input types encompassed by this input type. This field can be used
	// to define aggregate input types.
	Children InputTypes
}

// Matches returns true if the name of this input type or any of its children exactly
// match the given input type string.
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

// InputTypes is a slice of InputType objects.
type InputTypes []*InputType

// FromString returns the first InputType where either its name or aliases match the
// given input type string. This method is case-insensitive.
func (t InputTypes) FromString(inputType string) (*InputType, error) {
	inputType = strings.ToLower(inputType)
	for _, i := range t {
		if strings.ToLower(i.Name) == inputType {
			return i, nil
		}
		for _, a := range i.Aliases {
			if strings.ToLower(a) == inputType {
				return i, nil
			}
		}
	}
	return nil, fmt.Errorf("Unrecognized input type")
}

// Arm represents Azure Resource Manager template inputs.
var Arm = &InputType{
	Name: "arm",
}

// CloudFormation represents CloudFormation template inputs.
var CloudFormation = &InputType{
	Name:    "cfn",
	Aliases: []string{"cloudformation"},
}

// CloudScan represents inputs from a Snyk Cloud Scan.
var CloudScan = &InputType{
	Name:    "cloud_scan",
	Aliases: []string{"cloud-scan"},
	Children: InputTypes{
		TerraformState,
	},
}

// Kubernetes represents Kubernetes manifest inputs.
var Kubernetes = &InputType{
	Name:    "k8s",
	Aliases: []string{"kubernetes"},
}

// TerraformHCL represents Terraform HCL source code inputs.
var TerraformHCL = &InputType{
	Name:    "tf_hcl",
	Aliases: []string{"tf-hcl"},
}

// TerraformPlan represents Terraform Plan JSON inputs.
var TerraformPlan = &InputType{
	Name:    "tf_plan",
	Aliases: []string{"tf-plan"},
}

// TerraformState represents Terraform State JSON inputs.
var TerraformState = &InputType{
	Name:    "tf_state",
	Aliases: []string{"tf-state"},
}

// Terraform is an aggregate input type that encompasses all input types that contain
// Terraform resource types.
var Terraform = &InputType{
	Name:    "tf",
	Aliases: []string{"terraform"},
	Children: InputTypes{
		TerraformHCL,
		TerraformPlan,
		CloudScan,
	},
}
