package cfn_schemas

type Type int

const (
	Unknown Type = iota
	Boolean
	Integer
	Number
	String
	Array
	Object
)

// A Schema correponds to a resource or a subtree of a resource.
// They may contain infinite loops.
type Schema struct {
	Type       Type
	Properties map[string]*Schema
	Items      *Schema
}

// We only need one.
var unknownSchema = &Schema{Type: Unknown}

func (schema schema) convert() *Schema {
	// Declare definitions first so they can be reused.
	definitions := map[string]*Schema{}
	for key := range schema.Definitions {
		definitions[key] = &Schema{}
	}

	// Property conversion resolves references in `Definitions`.
	var convertProperty func(property) *Schema
	convertProperty = func(prop property) *Schema {
		if prop.IsRef() {
			if def, ok := definitions[prop.GetRef()]; ok {
				return def
			} else {
				return unknownSchema
			}
		} else {
			out := Schema{
				Type:       prop.GetType(),
				Properties: nil,
				Items:      nil,
			}
			if len(prop.Properties) > 0 {
				out.Properties = map[string]*Schema{}
				for k, v := range prop.Properties {
					out.Properties[k] = convertProperty(v)
				}
			}
			if prop.Items != nil {
				out.Items = convertProperty(*prop.Items)
			}
			return &out
		}
	}

	// Convert definitions.
	for k, def := range definitions {
		out := convertProperty(schema.Definitions[k])
		def.Type = out.Type
		def.Properties = out.Properties
		def.Items = out.Items
	}

    // Convert properties.
	properties := map[string]*Schema{}
	for key, prop := range schema.Properties {
		properties[key] = convertProperty(prop)
	}

    // Return schema.
	return &Schema{
		Type:       Object,
		Properties: properties,
	}
}
