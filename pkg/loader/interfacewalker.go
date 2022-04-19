package loader

// This is a utility for recursively transforming JSON-like interface values in
// go.
//
// At every step, the transformer returns the new value as well as an indication
// of whether or not we should continue.
type topDownInterfaceWalker interface {
	walkObject(map[string]interface{}) (interface{}, bool)
	walkArray([]interface{}) (interface{}, bool)
}

func topDownWalkInterface(w topDownInterfaceWalker, value interface{}) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		updated, cont := w.walkObject(v)
		if cont {
			return topDownWalkChildren(w, updated)
		} else {
			return updated
		}
	case []interface{}:
		updated, cont := w.walkArray(v)
		if cont {
			return topDownWalkChildren(w, updated)
		} else {
			return updated
		}
	default:
		return value
	}
}

func topDownWalkChildren(w topDownInterfaceWalker, value interface{}) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		for k, c := range v {
			v[k] = topDownWalkInterface(w, c)
		}
		return v
	case []interface{}:
		for i, c := range v {
			v[i] = topDownWalkInterface(w, c)
		}
		return v
	default:
		return value
	}
}
