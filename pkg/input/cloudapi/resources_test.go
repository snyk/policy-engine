package cloudapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

type resourcesOutput struct {
	resources []ResourceObject
	err       error
}

type resourcesResp struct {
	expectedURL string
	coll        CollectionDocumentRes
	err         string
}

type resourcesTestCase struct {
	name      string
	params    ResourcesParameters
	responses []resourcesResp
	expected  resourcesOutput
}

func TestResources(t *testing.T) {
	testCases := []resourcesTestCase{
		{
			name: "single page of resources",
			params: ResourcesParameters{
				ResourceType: []string{
					"some_resource_type",
				},
			},
			responses: []resourcesResp{
				{
					expectedURL: "/rest/orgs/org-id/cloud/resources?kind=cloud&resource_type=some_resource_type&version=2022-04-13~experimental",
					coll: CollectionDocumentRes{
						Data: []ResourceObject{
							{
								ID:   "some-resource",
								Type: "some_resource_type",
							},
						},
					},
				},
			},
			expected: resourcesOutput{
				resources: []ResourceObject{
					{
						ID:   "some-resource",
						Type: "some_resource_type",
					},
				},
			},
		},
		{
			name: "multiple pages of resources",
			params: ResourcesParameters{
				ResourceType: []string{
					"some_resource_type",
					"another_resource_type",
				},
			},
			responses: []resourcesResp{
				{
					expectedURL: "/rest/orgs/org-id/cloud/resources?kind=cloud&resource_type=some_resource_type&resource_type=another_resource_type&version=2022-04-13~experimental",
					coll: CollectionDocumentRes{
						Data: []ResourceObject{
							{
								ID:   "some-resource",
								Type: "some_resource_type",
							},
						},
						Links: Links{
							Next: "/next-page",
						},
					},
				},
				{
					expectedURL: "/next-page",
					coll: CollectionDocumentRes{
						Data: []ResourceObject{
							{
								ID:   "another-resource",
								Type: "another_resource_type",
							},
						},
					},
				},
			},
			expected: resourcesOutput{
				resources: []ResourceObject{
					{
						ID:   "some-resource",
						Type: "some_resource_type",
					},
					{
						ID:   "another-resource",
						Type: "another_resource_type",
					},
				},
			},
		},
		{
			name: "http error",
			params: ResourcesParameters{
				ResourceType: []string{
					"some_resource_type",
				},
			},
			responses: []resourcesResp{
				{
					expectedURL: "/rest/orgs/org-id/cloud/resources?kind=cloud&resource_type=some_resource_type&version=2022-04-13~experimental",
					err:         "some error",
				},
			},
			expected: resourcesOutput{
				err: ErrFetchingResources,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			respIdx := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp := tc.responses[respIdx]

				assert.Equal(t, r.Method, http.MethodGet)
				assert.Equal(t, resp.expectedURL, r.URL.String())
				assert.Equal(t, "application/vnd.api+json", r.Header.Get("Content-Type"))
				assert.Equal(t, "some-token", r.Header.Get("Authorization"))

				if resp.err != "" {
					http.Error(w, resp.err, 500)
					return
				}
				raw, err := json.Marshal(resp.coll)
				if err != nil {
					t.Fatal(err)
				}
				w.Write(raw)
				respIdx += 1
			}))
			defer server.Close()

			client, err := NewClient(ClientConfig{
				URL:     server.URL,
				Token:   "some-token",
				Version: "2022-04-13~experimental",
			})
			assert.NoError(t, err)

			got, err := client.Resources(context.TODO(), "org-id", tc.params)
			assert.Equal(t, tc.expected.resources, got)
			assert.ErrorIs(t, err, tc.expected.err)
		})
	}
}
