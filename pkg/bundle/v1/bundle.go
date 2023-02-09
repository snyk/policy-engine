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
	"gopkg.in/yaml.v3"
)

const VERSION = "v1"

type VcsMetadata struct {
	Type string `json:"type"`
	Uri  string `json:"uri"`
}

type Manifest struct {
	base.Manifest
	PolicyEngineVersion string      `json:"policy_engine_version"`
	Revision            string      `json:"revision"`
	Vcs                 VcsMetadata `json:"vcs"`
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
	files    map[string][]byte
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
	b.files[path] = raw
	return nil
}

func (b *Bundle) addModule(path string, raw []byte) error {
	module, err := ast.ParseModule(path, string(raw))
	if err != nil {
		return err
	}
	b.modules[path] = module
	b.files[path] = raw
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

func NewBundle(p base.FileProducer) (base.Bundle, error) {
	info := p.Info()
	bundle := &Bundle{
		info:     info,
		document: map[string]interface{}{},
		modules:  map[string]*ast.Module{},
		files:    map[string][]byte{},
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

func (b *Bundle) Modules() map[string]*ast.Module {
	return b.modules
}

func (b *Bundle) Document() map[string]interface{} {
	return b.document
}

func (b *Bundle) SourceInfo() base.SourceInfo {
	return b.info
}

// func (b *Bundle) Info() *models.RuleBundleInfo {
// 	return &models.RuleBundleInfo{
// 		Name:     b.SourceInfo().FileInfo.Path,
// 		Source:   b.Sourc,
// 		Checksum: b.Info().Checksum,
// 	}
// }
