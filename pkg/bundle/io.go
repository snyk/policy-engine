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

package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/snyk/policy-engine/pkg/bundle/base"
)

var ErrMissingManifest = errors.New("missing manifest.json")
var ErrUnableToReadManifest = errors.New("unable to read manifest.json")
var ErrManifestNotRegular = errors.New("manifest.json not a regular file")

const (
	ARCHIVE   base.SourceType = "archive"
	DIRECTORY base.SourceType = "directory"
)

type TarGzReader struct {
	path string
	raw  []byte
}

func NewTarGzReader(path string, r io.Reader) (base.Reader, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return &TarGzReader{
		path: path,
		raw:  raw,
	}, nil
}

func (r *TarGzReader) Info() base.SourceInfo {
	return base.SourceInfo{
		SourceType: ARCHIVE,
		FileInfo: base.FileInfo{
			Path:     r.path,
			Checksum: Checksum(r.raw),
		},
	}
}

func (r *TarGzReader) WalkFiles(handler base.WalkFilesFunc) error {
	gzf, err := gzip.NewReader(bytes.NewReader(r.raw))
	if err != nil {
		return err
	}
	defer gzf.Close()
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
			if err := handler(path, tarReader); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *TarGzReader) Manifest() (*base.Manifest, error) {
	gzf, err := gzip.NewReader(bytes.NewReader(r.raw))
	if err != nil {
		return nil, err
	}
	defer gzf.Close()
	tarReader := tar.NewReader(gzf)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			gzf.Close()
			return nil, err
		}
		if filepath.Base(header.Name) == "manifest.json" {
			raw, err := io.ReadAll(tarReader)
			if err != nil {
				return nil, err
			}
			manifest := &base.Manifest{}
			if err := json.Unmarshal(raw, manifest); err != nil {
				return nil, fmt.Errorf("%s: %w: %v", r.path, ErrUnableToReadManifest, err)
			}
			return manifest, nil
		}
	}
	return nil, fmt.Errorf("%s: %w", r.path, ErrMissingManifest)
}

type DirReader struct {
	path string
}

func NewDirReader(path string) base.Reader {
	return &DirReader{
		path: path,
	}
}

func (r *DirReader) Info() base.SourceInfo {
	return base.SourceInfo{
		SourceType: DIRECTORY,
		FileInfo: base.FileInfo{
			Path: r.path,
		},
	}
}

func (r *DirReader) WalkFiles(handler base.WalkFilesFunc) error {
	wdf := walkDirFunc(r.path, handler)
	return filepath.WalkDir(r.path, wdf)
}

func (r *DirReader) Manifest() (*Manifest, error) {
	path := filepath.Join(r.path, "manifest.json")
	info, err := os.Stat(path)
	if err == os.ErrNotExist {
		return nil, fmt.Errorf("%s: %w", r.path, ErrMissingManifest)
	} else if err != nil {
		return nil, fmt.Errorf("%s: %w: %v", r.path, ErrUnableToReadManifest, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", r.path, ErrManifestNotRegular)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %v", r.path, ErrUnableToReadManifest, err)
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %v", r.path, ErrUnableToReadManifest, err)
	}
	manifest := &base.Manifest{}
	if err := json.Unmarshal(raw, manifest); err != nil {
		return nil, fmt.Errorf("%s: %w: %v", r.path, ErrUnableToReadManifest, err)
	}
	return manifest, nil
}

type FSReader struct {
	path string
	fsys fs.FS
}

func NewFSReader(path string, fsys fs.FS) base.Reader {
	return &FSReader{
		path: path,
		fsys: fsys,
	}
}

func (r *FSReader) Info() base.SourceInfo {
	return base.SourceInfo{
		SourceType: DIRECTORY,
		FileInfo: base.FileInfo{
			Path: r.path,
		},
	}
}

func (r *FSReader) WalkFiles(handler base.WalkFilesFunc) error {
	wdf := walkDirFunc(r.path, handler)
	return fs.WalkDir(r.fsys, r.path, wdf)
}

func (r *FSReader) Manifest() (*Manifest, error) {
	path := filepath.Join(r.path, "manifest.json")
	info, err := fs.Stat(r.fsys, path)
	if err == os.ErrNotExist {
		return nil, fmt.Errorf("%s: %w", r.path, ErrMissingManifest)
	} else if err != nil {
		return nil, fmt.Errorf("%s: %w: %v", r.path, ErrUnableToReadManifest, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", r.path, ErrManifestNotRegular)
	}
	f, err := r.fsys.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %v", r.path, ErrUnableToReadManifest, err)
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %v", r.path, ErrUnableToReadManifest, err)
	}
	manifest := &base.Manifest{}
	if err := json.Unmarshal(raw, manifest); err != nil {
		return nil, fmt.Errorf("%s: %w: %v", r.path, ErrUnableToReadManifest, err)
	}
	return manifest, nil
}

func walkDirFunc(basePath string, handler base.WalkFilesFunc) fs.WalkDirFunc {
	return func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(basePath, path)
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		return handler(rel, f)
	}
}

type FileProducer struct {
	Reader base.Reader
	Filter func(path string) bool
}

func (p *FileProducer) Produce(consumer base.FileConsumer) error {
	return p.Reader.WalkFiles(func(path string, f io.Reader) error {
		path = filepath.ToSlash(filepath.Clean(path))
		if p.Filter != nil && !p.Filter(path) {
			return nil
		}
		raw, err := io.ReadAll(f)
		if err != nil {
			return err
		}
		consumer(base.File{
			Raw: raw,
			Info: base.FileInfo{
				Path:     path,
				Checksum: Checksum(raw),
			},
		})
		return nil
	})
}

func (p *FileProducer) Info() base.SourceInfo {
	return p.Reader.Info()
}

func Checksum(raw []byte) string {
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("%x", sum)
}

type TarGzWriter struct {
	writer io.Writer
}

func NewTarGzWriter(w io.Writer) base.Writer {
	return &TarGzWriter{
		writer: w,
	}
}

func (w *TarGzWriter) Write(b Bundle) error {
	gw := gzip.NewWriter(w.writer)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()
	for path, mod := range b.Modules() {
		bytes := []byte(mod.String())
		if err := writeToTar(tw, path, bytes); err != nil {
			return err
		}
	}
	bytes, err := json.Marshal(b.Document())
	if err != nil {
		return err
	}
	if err := writeToTar(tw, "data.json", bytes); err != nil {
		return err
	}
	bytes, err = json.Marshal(b.Manifest())
	if err != nil {
		return err
	}
	return writeToTar(tw, "manifest.json", bytes)
}

func writeToTar(tw *tar.Writer, path string, b []byte) error {
	hdr := &tar.Header{
		Name:     path,
		Mode:     0600,
		Typeflag: tar.TypeReg,
		Size:     int64(len(b)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := tw.Write(b); err != nil {
		return err
	}
	return nil
}
