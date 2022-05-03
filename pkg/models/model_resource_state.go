/*
 * Unified Policy Engine I/O Formats
 *
 * Documentation for the input and output formats used in Unified Policy Engine
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package models

// The state of a single resource
type ResourceState struct {
	// The identifier of the object. This can be a natural ID. It is assumed that this ID is unique within the namespace.
	Id string `json:"id"`
	// The type of the resource.
	ResourceType string `json:"resource_type"`
	// This field is a component of uniquely identifying a resource. It will resolve to different values depending on the input type and environment provider. For example, in a runtime AWS environment, this will be the region. For an IaC Terraform resource, this will be the module path. Customers of the API can set this to something that makes sense for them and parse it back.
	Namespace string `json:"namespace"`
	// Tags applied to the resource. Our goal is to extract tags into a uniform key->value format.
	Tags map[string]string `json:"tags,omitempty"`
	// This object is intended to hold any input type-specific or  environment-specific fields, e.g. provider, region, or source location.
	Meta map[string]interface{} `json:"meta,omitempty"`
	// A map of resource attributes. The only required entries are:   * id: An identifier for the resource. This can be a natural ID. It is         assumed that this ID is unique within the namespace.   * _type: The type of the resource.
	Attributes map[string]interface{} `json:"attributes"`
}
