package cloudapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClient(t *testing.T) {
	testCases := []struct {
		name                  string
		config                ClientConfig
		expectedURL           string
		expectedAuthorization string
		expectedVersion       string
		expectedError         error
	}{
		{
			name: "minimal options",
			config: ClientConfig{
				Token: "some-token",
			},
			expectedURL:           defaultURL,
			expectedAuthorization: "some-token",
			expectedVersion:       defaultVersion,
		},
		{
			name: "all options",
			config: ClientConfig{
				URL:     "https://api.dev.snyk.io",
				Token:   "some-token",
				Version: "2022-12-21~beta",
			},
			expectedURL:           "https://api.dev.snyk.io",
			expectedAuthorization: "some-token",
			expectedVersion:       "2022-12-21~beta",
		},
		{
			name: "missing scheme in URL",
			config: ClientConfig{
				URL:   "api.dev.snyk.io",
				Token: "some-token",
			},
			expectedURL:           "https://api.dev.snyk.io",
			expectedAuthorization: "some-token",
			expectedVersion:       defaultVersion,
		},
		{
			name: "URL with path",
			config: ClientConfig{
				URL:   "https://api.dev.snyk.io/api/v1",
				Token: "some-token",
			},
			expectedURL:           "https://api.dev.snyk.io/api/v1",
			expectedAuthorization: "some-token",
			expectedVersion:       defaultVersion,
		},
		{
			name:          "missing token",
			config:        ClientConfig{},
			expectedError: ErrMissingToken,
		},
		{
			name: "invalid URL",
			config: ClientConfig{
				URL:   "\x7f://api.dev.snyk.io",
				Token: "some-token",
			},
			expectedError: ErrInvalidURL,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewClient(tc.config)
			if tc.expectedError != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tc.expectedError)
			} else {
				assert.NotNil(t, client)
				assert.NotNil(t, client.httpClient)
				assert.Equal(t, tc.expectedAuthorization, client.authorization)
				assert.Equal(t, tc.expectedURL, client.url)
				assert.Equal(t, tc.expectedVersion, client.version)
			}
		})
	}
}
