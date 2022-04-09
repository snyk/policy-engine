// A replacement and simplification for the RegoProvider type in Regula.
package data

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func FSProvider(fsys fs.FS, basePath string) Provider {
	return func(_ context.Context, consumer Consumer) error {
		walkDirFunc := func(path string, d fs.DirEntry, readErr error) error {
			if readErr != nil {
				return readErr
			}
			if d.IsDir() {
				return nil
			}
			ext := filepath.Ext(path)
			if parser, ok := parsersByExtension[ext]; ok {
				reader, err := fsys.Open(path)
				if err != nil {
					return err
				}
				if err := parser(path, reader, consumer); err != nil {
					return err
				}
			}
			return nil
		}

		if err := fs.WalkDir(fsys, basePath, walkDirFunc); err != nil {
			return err
		}

		return nil
	}
}

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
				ext := filepath.Ext(basePath)
				if parser, ok := parsersByExtension[ext]; ok {
					reader, err := os.Open(path)
					if err != nil {
						return err
					}
					if err := parser(basePath, reader, consumer); err != nil {
						return err
					}
				}
			}
			return nil
		})
	}
}
