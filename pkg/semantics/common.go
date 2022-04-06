package semantics

type RegoResource struct {
	Id   string `json:"id"`
	Type string `json:"_type"`
}

type RegoDeny struct {
	Message  string       `json:"message,omitempty"`
	Resource *RegoResource `json:"resource,omitempty"`
}
