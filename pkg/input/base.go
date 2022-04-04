package input

type ResourcesByType = map[string]map[string]*Resource

type Resource struct {
	Id    string
	Type  string
	Value map[string]interface{}
}

type Input struct {
	Path      string
	Resources ResourcesByType
}
