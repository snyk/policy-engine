package bundle

import (
	"errors"
	"fmt"
	"strings"

	"github.com/snyk/policy-engine/pkg/bundle/base"
	v1 "github.com/snyk/policy-engine/pkg/bundle/v1"
)

var ErrUnrecognizedBundleFormatVersion = errors.New("unrecognized bundle format version")

func NewBundle(reader base.Reader) (base.Bundle, error) {
	manifest, err := reader.Manifest()
	if err != nil {
		return nil, err
	}
	producer := &FileProducer{
		Reader: reader,
		Filter: bundleFilter,
	}
	var b base.Bundle
	switch manifest.BundleFormatVersion {
	case v1.VERSION:
		b, err = v1.NewBundle(producer)
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnrecognizedBundleFormatVersion, manifest.BundleFormatVersion)
	}
	if err != nil {
		return nil, err
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return b, nil
}

func bundleFilter(path string) bool {
	if path == "manifest.json" {
		return true
	}
	return strings.HasPrefix(path, "rules/") || strings.HasPrefix(path, "lib/")
}
