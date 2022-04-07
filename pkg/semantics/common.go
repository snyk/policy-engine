package semantics

import (
	"fmt"
)

type RegoResource struct {
	Id   string `json:"id"`
	Type string `json:"_type"`
}

type RegoDeny struct {
	Correlation string        `json:"correlation,omitempty"`
	Message     string        `json:"message,omitempty"`
	Resource    *RegoResource `json:"resource,omitempty"`
}

func (d *RegoDeny) GetCorrelation() (string, error) {
	if d.Correlation != "" {
		return d.Correlation, nil
	}
	if d.Resource != nil {
		return d.Resource.Id, nil
	}
	return "", fmt.Errorf("No correlation or resource.id for deny block")
}
