package semantics

type RegoResource struct {
	Id   string `json:"id"`
	Type string `json:"_type"`
}

type RegoDeny struct {
	Correlation  string        `json:"correlation,omitempty"`
	Message      string        `json:"message,omitempty"`
	Resource     *RegoResource `json:"resource,omitempty"`
	ResourceType string        `json:"resource_type,omitempty"`
}

func (d *RegoDeny) GetCorrelation() string {
	if d.Correlation != "" {
		return d.Correlation
	}
	if d.Resource != nil {
		return d.Resource.Id
	}
	return ""
}

func (d *RegoDeny) GetResourceType() string {
	if d.ResourceType != "" {
		return d.ResourceType
	}
	if d.Resource != nil {
		return d.Resource.Type
	}
	return ""
}
