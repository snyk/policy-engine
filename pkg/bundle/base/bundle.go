package base

import (
	"github.com/open-policy-agent/opa/ast"
	"github.com/snyk/policy-engine/pkg/data"
)

type BundleSource string

type Manifest struct {
	BundleFormatVersion string `json:"bundle_format_version"`
}

type Bundle interface {
	Provider() data.Provider
	BundleFormatVersion() string
	Manifest() interface{}
	SourceInfo() SourceInfo
	Modules() map[string]*ast.Module
	Document() map[string]interface{}
	// Info() *models.RuleBundleInfo
}
