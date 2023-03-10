// © 2022-2023 Snyk Limited All rights reserved.
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

	embed "github.com/snyk/policy-engine/rego"
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
				defer reader.Close()
				if err := parser(ctx, basePath, path, reader, consumer); err != nil {
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
				ext := filepath.Ext(path)
				if parser, ok := parsersByExtension[ext]; ok {
					reader, err := os.Open(path)
					if err != nil {
						return err
					}
					defer reader.Close()
					if err := parser(ctx, root, path, reader, consumer); err != nil {
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
		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				break
			} else if err != nil {
				gzf.Close()
				return err
			}

			path := header.Name

			switch header.Typeflag {
			case tar.TypeReg:
				ext := filepath.Ext(path)
				if parser, ok := parsersByExtension[ext]; ok {
					if err != nil {
						gzf.Close()
						return err
					}
					if err := parser(ctx, "", path, tarReader, consumer); err != nil {
						gzf.Close()
						return err
					}
				}
			}
		}
		return gzf.Close()
	}
}

// Provides the pure rego version of the API.  Don't use this to evaluate rules
// in production.
func PureRegoBuiltinsProvider() Provider {
	return func(ctx context.Context, consumer Consumer) error {
		return regoParser(ctx, "", "snyk.rego", bytes.NewReader(embed.SnykRego), consumer)
	}
}

// Provides the pure rego part of the API.
func PureRegoLibProvider() Provider {
	return func(ctx context.Context, consumer Consumer) error {
		for path, rego := range embed.SnykLib {
			if err := regoParser(ctx, "", path, bytes.NewReader(rego), consumer); err != nil {
				return err
			}
		}
		return nil
	}
}
