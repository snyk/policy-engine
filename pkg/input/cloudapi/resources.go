package cloudapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/go-querystring/query"
)

type (
	ResourcesParameters struct {
		EnvironmentID []string `url:"environment_id,omitempty"`
		ResourceType  []string `url:"resource_type,omitempty"`
		ResourceID    []string `url:"resource_id,omitempty"`
		NativeID      []string `url:"native_id,omitempty"`
		ID            []string `url:"id,omitempty"`
		Platform      []string `url:"platform,omitempty"`
		Name          []string `url:"name,omitempty"`
		Location      []string `url:"location,omitempty"`
	}

	CollectionDocumentRes struct {
		Data  []ResourceObject `json:"data"`
		Links Links
	}

	ResourceObject struct {
		ID         string             `json:"id,omitempty"`
		Type       string             `json:"type"`
		Attributes ResourceAttributes `json:"attributes,omitempty"`
	}

	ResourceAttributes struct {
		Namespace    string                 `json:"namespace"`
		ResourceType string                 `json:"resource_type"`
		ResourceID   string                 `json:"resource_id"`
		State        map[string]interface{} `json:"state"`
		Tags         map[string]interface{} `json:"tags"`
	}

	Links struct {
		Next string `json:"next"`
	}
)

var ErrInitializingResourcesRequest = errors.New("failed to initialize resources request")
var ErrEncodingResourcesQuery = errors.New("failed to encode resources query")
var ErrFetchingResources = errors.New("failed to fetch resources")

func (c *Client) Resources(ctx context.Context, orgID string, params ResourcesParameters) (resources []ResourceObject, e error) {
	url := fmt.Sprintf("%s/rest/orgs/%s/cloud/resources", c.url, orgID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInitializingResourcesRequest, err)
	}
	q, err := query.Values(params)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncodingResourcesQuery, err)
	}
	q.Add("version", c.version)
	// We're hardcoding cloud here just to simplify things for now. If we do end
	// up with a use-case for IaC resources from the Cloud API, we'll need to
	// keep the input types in mind and produce multiple inputs from the
	// response.
	q.Add("kind", "cloud")
	req.URL.RawQuery = q.Encode()

	results, err := c.resourcesPage(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetchingResources, err)
	}
	resources = append(resources, results.Data...)

	for results.Links.Next != "" {
		url := fmt.Sprintf("%s/%s", c.url, strings.TrimPrefix(results.Links.Next, "/"))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInitializingResourcesRequest, err)
		}
		results, err = c.resourcesPage(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrFetchingResources, err)
		}
		resources = append(resources, results.Data...)
	}

	return resources, nil
}

func (c *Client) resourcesPage(ctx context.Context, req *http.Request) (CollectionDocumentRes, error) {
	var results CollectionDocumentRes

	req.Header.Set("Content-Type", "application/vnd.api+json")
	req.Header.Set("Authorization", c.authorization)

	res, err := c.httpClient.Do(req)
	if err != nil {
		return results, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return results, fmt.Errorf("invalid status code: %v", res.StatusCode)
	}

	body, _ := io.ReadAll(res.Body)
	if err := json.Unmarshal(body, &results); err != nil {
		return results, err
	}

	return results, nil
}
