// © 2023 Snyk Limited All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cloudapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
)

const (
	defaultURL     = "https://api.snyk.io"
	defaultVersion = "2022-04-13~experimental"
)

type ClientConfig struct {
	HTTPClient *http.Client
	URL        string
	Token      string
	Version    string
}

type Client struct {
	httpClient    *http.Client
	url           string
	authorization string
	version       string
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if c.authorization != "" {
		req.Header.Set("Authorization", c.authorization)
	}
	return c.httpClient.Do(req)
}

var ErrMissingToken = errors.New("no API token provided")
var ErrInvalidURL = errors.New("invalid URL")

func NewClient(config ClientConfig) (*Client, error) {
	// Authorization can either come from a pre-configured client or a token.
	if config.HTTPClient == nil && config.Token == "" {
		return nil, ErrMissingToken
	}

	u := config.URL
	if u == "" {
		u = defaultURL
	}

	// Prefer https if no scheme is specified, support http
	matched, err := regexp.MatchString("^https?://", u)
	if err != nil {
		return nil, err
	}
	if !matched {
		u = "https://" + u
	}

	v := config.Version
	if v == "" {
		v = defaultVersion
	}

	parsedURL, err := url.Parse(u)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}

	sanitizedURL := url.URL{
		Scheme: parsedURL.Scheme,
		Host:   parsedURL.Host,
		Path:   parsedURL.Path,
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	client := Client{
		httpClient:    httpClient,
		url:           sanitizedURL.String(),
		authorization: config.Token,
		version:       v,
	}

	return &client, nil
}

func NewClientFromEnv() (*Client, error) {
	return NewClient(ClientConfig{
		URL:     os.Getenv("SNYK_API"),
		Token:   os.Getenv("SNYK_TOKEN"),
		Version: os.Getenv("SNYK_API_VERSION"),
	})
}
