package cloudapi

import (
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

func NewClientFromEnv() (*Client, error) {
	return NewClient(ClientConfig{
		URL:     os.Getenv("SNYK_API"),
		Token:   os.Getenv("SNYK_TOKEN"),
		Version: os.Getenv("SNYK_API_VERSION"),
	})
}
