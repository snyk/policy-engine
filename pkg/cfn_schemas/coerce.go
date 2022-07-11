package cfn_schemas

import (
	"fmt"
	"strconv"
	"strings"
)

func Coerce(val interface{}, schema *Schema) interface{} {
	if schema == nil || schema.Type == Unknown {
		return val
	}

	switch v := val.(type) {
	case []interface{}:
		return CoerceArray(v, schema)
	case map[string]interface{}:
		return CoerceObject(v, schema)
	case string:
		switch schema.Type {
		case String:
			return v
		case Boolean:
			return strings.ToLower(v) == "true"
		case Integer:
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
		case Number:
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				return f
			}
		}
	case int:
		switch schema.Type {
		case String:
			return fmt.Sprintf("%d", v)
		}
	case float64:
		switch schema.Type {
		case String:
			return fmt.Sprintf("%f", v)
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
