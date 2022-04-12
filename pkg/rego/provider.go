// A replacement and simplification for the RegoProvider type in Regula.
package rego

import (
	"context"
	"io/fs"
	"io/ioutil"
	"path/filepath"
	"strings"
)

type Provider func(context.Context, Consumer) error

func LocalProvider(root string) Provider {
	return func(ctx context.Context, consumer Consumer) error {
		return filepath.Walk(root, func(path string, d fs.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				basePath := strings.TrimPrefix(path, root)
				if path == root {
					// If a rego file is passed directly, consider the whole
					// path, otherwise we'd end up with an empty basePath.
					basePath = path
				}

				switch filepath.Ext(basePath) {
				case ".rego":
					bytes, err := ioutil.ReadFile(path)
					if err != nil {
						return err
					}
					if err := consumer.Module(basePath, bytes); err != nil {
						return err
					}
				case ".json", ".yaml", ".yml":
					bytes, err := ioutil.ReadFile(path)
					if err != nil {
						return err
					}
					if err := consumer.DataDocument(basePath, bytes); err != nil {
						return err
					}
				}
			}
			return nil
		})
	}
}
