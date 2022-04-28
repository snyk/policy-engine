// A replacement and simplification for the RegoProvider type in Regula.
package data

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	embed "github.com/snyk/unified-policy-engine/rego"
)

func FSProvider(fsys fs.FS, basePath string) Provider {
	return func(ctx context.Context, consumer Consumer) error {
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
				if err := parser(ctx, path, reader, consumer); err != nil {
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
					if err := parser(ctx, basePath, reader, consumer); err != nil {
						return err
					}
				}
			}
			return nil
		})
	}
}

func TarGzProvider(reader io.Reader) Provider {
	return func(ctx context.Context, consumer Consumer) error {
		gzf, err := gzip.NewReader(reader)
		if err != nil {
			return err
		}

		tarReader := tar.NewReader(gzf)
		for true {
			header, err := tarReader.Next()
			if err == io.EOF {
				break
			} else if err != nil {
				return err
			}

			path := header.Name

			switch header.Typeflag {
			case tar.TypeReg:
				ext := filepath.Ext(path)
				if parser, ok := parsersByExtension[ext]; ok {
					if err != nil {
						return err
					}
					if err := parser(ctx, path, tarReader, consumer); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
}

// Provides the pure rego version of the API.  Don't use this to evaluate rules
// in production.
func PureRegoProvider() Provider {
	return func(ctx context.Context, consumer Consumer) error {
		err := regoParser(ctx, "snyk.rego", bytes.NewReader(embed.SnykRego), consumer)
		if err != nil {
			return nil
		}
		return nil
	}
}
