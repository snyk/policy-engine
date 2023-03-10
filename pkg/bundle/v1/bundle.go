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

package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/snyk/policy-engine/pkg/bundle/base"
	"github.com/snyk/policy-engine/pkg/data"
	"github.com/snyk/policy-engine/pkg/interfacetricks"
	"github.com/snyk/policy-engine/pkg/version"
	"gopkg.in/yaml.v3"
)

const VERSION = "v1"

type VCSMetadata struct {
	Type string `json:"type"`
	URI  string `json:"uri"`
}

type Manifest struct {
	base.Manifest
	PolicyEngineVersion string      `json:"policy_engine_version"`
	Revision            string      `json:"revision"`
	VCS                 VCSMetadata `json:"vcs"`
}

var ErrInvalidManifest = errors.New("invalid manifest")

func (m *Manifest) Validate() error {
	if m.BundleFormatVersion != VERSION {
		return fmt.Errorf(
			"%w: missing or invalid bundle format version: %s",
			ErrInvalidManifest,
			m.BundleFormatVersion,
		)
	}
	return nil
}

type Bundle struct {
	info     base.SourceInfo
	document map[string]interface{}
	modules  map[string]*ast.Module
	manifest Manifest
}

func (b *Bundle) addDocument(path string, raw []byte) error {
	var document interface{}
	if err := yaml.Unmarshal(raw, &document); err != nil {
		return err
	}
	prefix := []string{}
	split := strings.Split(path, "/")
	if len(split) < 1 {
		return fmt.Errorf("empty or malformed path: %s", path)
	}
	for _, part := range split[:len(split)-1] {
		if part != "" && part != "." {
			prefix = append(prefix, part)
		}
	}
	for i := len(prefix) - 1; i >= 0; i-- {
		document = map[string]interface{}{
			prefix[i]: document,
		}
	}
	// Must be an object at this point to conform to OPA API.
	switch doc := document.(type) {
	case map[string]interface{}:
		b.document = interfacetricks.MergeObjects(b.document, doc)
	default:
		return fmt.Errorf("root data document needs to be object not array: %s", path)
	}
	return nil
}

func (b *Bundle) addModule(path string, raw []byte) error {
	module, err := ast.ParseModule(path, string(raw))
	if err != nil {
		return err
	}
	b.modules[path] = module
	return nil
}

func (b *Bundle) addManifest(path string, raw []byte) error {
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return err
	}
	b.manifest = manifest
	return nil
}

var ErrInvalidBundle = errors.New("invalid bundle")

func (b *Bundle) Validate() error {
	if err := b.manifest.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidBundle, err)
	}
	if len(b.modules) < 1 {
		return fmt.Errorf("%w: no rego code found", ErrInvalidBundle)
	}
	return nil
}

func (b *Bundle) BundleFormatVersion() string {
	return b.manifest.BundleFormatVersion
}

func (b *Bundle) Provider() data.Provider {
	return func(ctx context.Context, c data.Consumer) error {
		for p, m := range b.modules {
			if err := c.Module(ctx, p, m); err != nil {
				return err
			}
		}
		return c.DataDocument(ctx, "", b.document)
	}
}

func (b *Bundle) Manifest() interface{} {
	return b.manifest
}

func (b *Bundle) Modules() map[string]*ast.Module {
	return b.modules
}

func (b *Bundle) Document() map[string]interface{} {
	return b.document
}

func (b *Bundle) SourceInfo() base.SourceInfo {
	return b.info
}

func ReadBundle(p base.FileProducer) (base.Bundle, error) {
	info := p.Info()
	bundle := &Bundle{
		info:     info,
		document: map[string]interface{}{},
		modules:  map[string]*ast.Module{},
	}
	consumer := func(f base.File) error {
		path := f.Info.Path
		raw := f.Raw
		if f.Info.Path == "manifest.json" {
			return bundle.addManifest(path, raw)
		}
		switch filepath.Ext(f.Info.Path) {
		case ".rego":
			return bundle.addModule(path, raw)
		case ".yml", ".yaml", ".json":
			return bundle.addDocument(path, raw)
		default:
			return nil
		}
	}
	if err := p.Produce(consumer); err != nil {
		return nil, err
	}
	return bundle, nil
}

type ManifestOption func(m *Manifest)

func BuildBundle(p base.FileProducer, opts ...ManifestOption) (base.Bundle, error) {
	manifest := Manifest{}
	for _, opt := range opts {
		opt(&manifest)
	}
	manifest.BundleFormatVersion = VERSION
	manifest.PolicyEngineVersion = version.Version
	bundle := &Bundle{
		manifest: manifest,
		document: map[string]interface{}{},
		modules:  map[string]*ast.Module{},
	}
	consumer := func(f base.File) error {
		path := f.Info.Path
		raw := f.Raw
		if f.Info.Path == "manifest.json" {
			return nil
		}
		switch filepath.Ext(f.Info.Path) {
		case ".rego":
			return bundle.addModule(path, raw)
		case ".yml", ".yaml", ".json":
			return bundle.addDocument(path, raw)
		default:
			return nil
		}
	}
	if err := p.Produce(consumer); err != nil {
		return nil, err
	}
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	return bundle, nil
}

func WithRevision(r string) ManifestOption {
	return func(m *Manifest) {
		m.Revision = r
	}
}

func WithVCSType(t string) ManifestOption {
	return func(m *Manifest) {
		m.VCS.Type = t
	}
}

func WithVCSURI(u string) ManifestOption {
	return func(m *Manifest) {
		m.VCS.URI = u
	}
}
