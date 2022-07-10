package cfn_schemas

import (
	"strconv"
)

func Coerce(val interface{}, schema *Schema) interface{} {
	switch v := val.(type) {
	case []interface{}:
		return CoerceArray(v, schema)
	case map[string]interface{}:
		return CoerceObject(v, schema)
	case string:
		switch schema.Type {
		case String:
			return v
		case Integer:
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
		}
	}

	return val
}

func CoerceArray(arr []interface{}, schema *Schema) []interface{} {
	if schema.Type != Array || schema.Items == nil {
		return arr
	}

	coerce := make([]interface{}, len(arr))
	for i, v := range arr {
		coerce[i] = Coerce(v, schema.Items)
	}
	return coerce
}

func CoerceObject(obj map[string]interface{}, schema *Schema) map[string]interface{} {
	if schema.Type != Object {
		return obj
	}

	coerce := map[string]interface{}{}
	for k, v := range obj {
		if s, ok := schema.Properties[k]; ok {
			coerce[k] = Coerce(v, s)
		} else {
			coerce[k] = v
		}
	}
	return coerce
}
