package upe

import (
	"encoding/json"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// Metadata is passed to OPA as documents.  We'll need to be able to load
// this from bundles as well.
type Metadata struct {
	documents map[string]interface{}
}

func EmptyMetadata() *Metadata {
	return &Metadata{map[string]interface{}{}}
}

func LoadMetadataDirectory(dir string) (*Metadata, error) {
	metadata := EmptyMetadata()
	err := filepath.Walk(dir, func(path string, d fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			if filepath.Ext(path) == ".json" {
				prefixPath := filepath.Dir(strings.TrimPrefix(path, dir))
				prefix := []string{}
				for _, part := range strings.Split(prefixPath, string(os.PathSeparator)) {
					if part != "" {
						prefix = append(prefix, part)
					}
				}
				meta, err := LoadMetadataFile(path, prefix)
				if err != nil {
					return err
				}
				metadata.Merge(meta)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return metadata, nil
}

func LoadMetadataFile(path string, prefix []string) (*Metadata, error) {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	documents := map[string]interface{}{}
	if err := json.Unmarshal(contents, &documents); err != nil {
		return nil, err
	}

	for i := len(prefix) - 1; i >= 0; i-- {
		documents = map[string]interface{}{
			prefix[i]: documents,
		}
	}

	return &Metadata{documents: documents}, err
}

// Copy Metadata from another Metadata object into this one
func (meta *Metadata) Merge(other *Metadata) {
	merge(meta.documents, other.documents)
}

func merge(left interface{}, right interface{}) interface{} {
	switch l := left.(type) {
	case map[string]interface{}:
		switch r := right.(type) {
		case map[string]interface{}:
			for k, rv := range r {
				if lv, ok := l[k]; ok {
					merge(lv, rv)
				} else {
					l[k] = rv
				}
			}
		}
	case []interface{}:
		switch r := right.(type) {
		case []interface{}:
			length := len(l)
			if len(r) > length {
				length = len(r)
			}
			arr := make([]interface{}, length)
			for i := 0; i < length; i++ {
				if i < len(l) && i < len(r) {
					arr[i] = merge(l[i], r[i])
				} else if i < len(l) {
					arr[i] = l[i]
				} else if i < len(r) {
					arr[i] = r[i]
				} else {
					arr[i] = nil
				}
			}
			return arr
		}
	}

	return left
}
