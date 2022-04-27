package interfacetricks

func Copy(value interface{}) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		obj := make(map[string]interface{}, len(v))
		for k, attr := range v {
			obj[k] = Copy(attr)
		}
		return obj
	case []interface{}:
		arr := make([]interface{}, len(v))
		for i, attr := range v {
			arr[i] = Copy(attr)
		}
		return arr
	default:
		return v
	}
}
