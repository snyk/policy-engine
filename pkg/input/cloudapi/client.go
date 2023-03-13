package cloudapi

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
)

type ClientConfig struct {
	URL     string
	Token   string
	Version string
}

type Client struct {
	httpClient    *http.Client
	url           string
	authorization string
	version       string
}

func NewClient(config ClientConfig) (*Client, error) {
	if config.Token == "" {
		return nil, fmt.Errorf("no token provided")
	}

	u := config.URL
	if u == "" {
		u = "https://api.snyk.io"
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
		v = "2022-04-13~experimental"
	}

	parsedURL, err := url.Parse(u)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	sanitizedURL := url.URL{
		Scheme: parsedURL.Scheme,
		Host:   parsedURL.Host,
	}

	client := Client{
		httpClient:    http.DefaultClient,
		url:           sanitizedURL.String(),
		authorization: config.Token,
		version:       v,
	}

	return &client, nil
}
