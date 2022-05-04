package interfacetricks

// Recursively test equality of two value trees.
func Equal(left interface{}, right interface{}) bool {
	switch l := left.(type) {
	case []interface{}:
		if r, ok := right.([]interface{}); ok {
			if len(l) != len(r) {
				return false
			}
			for i := range l {
				if !Equal(l[i], r[i]) {
					return false
				}
			}
			return true
		} else {
			return false
		}
	case map[string]interface{}:
		if r, ok := right.(map[string]interface{}); ok {
			if len(l) != len(r) {
				return false
			}
			for k, lv := range l {
				rv, ok := r[k]
				if !ok || !Equal(lv, rv) {
					return false
				}
			}
			return true
		} else {
			return false
		}
	default:
		return left == right
	}
}
