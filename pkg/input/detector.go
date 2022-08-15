// Copyright 2022 Snyk Ltd
// Copyright 2021 Fugue, Inc.
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

package input

import (
	"fmt"
	"path/filepath"

	"github.com/snyk/policy-engine/pkg/models"
	"github.com/spf13/afero"
)

// IACConfiguration is a loaded IaC Configuration.
type IACConfiguration interface {
	// ToState() returns the input for the rule engine.
	ToState() models.State
	// LoadedFiles are all of the files contained within this configuration.
	LoadedFiles() []string
	// Location resolves an attribute path to to a file, line and column.
	// If we are working with a resource-based input, the first three elements
	// of the attributePath are: resource namespace, type, and ID.
	Location(attributePath []interface{}) (LocationStack, error)
	// Some files may load but still have errors in them.  You can retrieve
	// them here.
	Errors() []error
}

// Location is a filepath, line and column.
type Location struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Col  int    `json:"column"`
}

// LocationStack represents a stack of Locations. It is conceptually similar to a call
// stack. An example of when we would have more than one location for a resource or
// attribute:
//
//     attribute "foo" at line 4...
//     included in "rds" module at line 8...
//     included in "main" module at line 3...
//
// These are stored as a call stack, with the most specific location in the
// first position, and the "root of the call stack" at the last position.
type LocationStack = []Location

// String returns a string representation of this Location
func (l Location) String() string {
	return fmt.Sprintf("%s:%d:%d", l.Path, l.Line, l.Col)
}

// DetectOptions are options passed to the configuration detectors.
type DetectOptions struct {
	// IgnoreExt instructs the detector to ignore file extensions.
	IgnoreExt bool
	// VarFiles contains paths to variable files that should be included in the
	// configurations that the detector parses.
	VarFiles []string
}

// Detector implements the visitor part of the visitor pattern for the concrete
// Detectable implementations. A Detector implementation must contain functions to visit
// both directories and files. An empty implementation must return nil, nil to indicate
// that the InputPath has been ignored.
type Detector interface {
	// DetectDirectory attempts to detect an IaC configuration in the given directory.
	// If no configuration is detected and no errors occurred, this method is expected
	// to return nil, nil.
	DetectDirectory(i *Directory, opts DetectOptions) (IACConfiguration, error)
	// DetectDirectory attempts to detect an IaC configuration in the given file. If
	// no configuration is detected and no errors occurred, this method is expected to
	// return nil, nil.
	DetectFile(i *File, opts DetectOptions) (IACConfiguration, error)
}

// Detectable is a generic interface to represent inputs for a ConfigurationDetector.
type Detectable interface {
	DetectType(d Detector, opts DetectOptions) (IACConfiguration, error)
	GetPath() string
}

// WalkFunc is a callback that's invoked on each descendent of an Directory. It
// returns a boolean that, when true, indicates that the caller should not call d.Walk()
// on this detectable. The depth argument is a 0-based representation of how many
// directories have been traversed since the original Walk call.
type WalkFunc func(d Detectable, depth int) (skip bool, err error)

// NewDetectable is a helper to produce one of the concrete Detectable implementations
// from the given path.
func NewDetectable(fs afero.Fs, path string) (Detectable, error) {
	info, err := fs.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return &Directory{
			Fs:   fs,
			Path: path,
		}, nil
	} else {
		return &File{
			Fs:   fs,
			Path: path,
		}, nil
	}
}

// Directory is a Detectable implementation that represents a directory.
type Directory struct {
	Path     string
	Fs       afero.Fs
	children []Detectable
	loaded   bool
}

// DetectType will invoke the given detector on this directory.
func (d *Directory) DetectType(c Detector, opts DetectOptions) (IACConfiguration, error) {
	return c.DetectDirectory(d, opts)
}

// Children returns the contents of this directory.
func (d *Directory) Children() ([]Detectable, error) {
	if d.loaded {
		return d.children, nil
	}
	entries, err := afero.ReadDir(d.Fs, d.Path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", UnableToReadDir, err)
	}
	for _, e := range entries {
		n := e.Name()
		p := filepath.Join(d.Path, n)
		if e.IsDir() {
			d.children = append(d.children, &Directory{
				Path: p,
				Fs:   d.Fs,
			})
		} else {
			d.children = append(d.children, &File{
				Path: p,
				Fs:   d.Fs,
			})
		}
	}
	d.loaded = true
	return d.children, nil
}

func (d *Directory) walk(w WalkFunc, depth int) error {
	nextDepth := depth + 1
	children, err := d.Children()
	if err != nil {
		return err
	}
	for _, c := range children {
		skip, err := w(c, nextDepth)
		if err != nil {
			return err
		}
		if skip {
			continue
		}
		if dir, ok := c.(*Directory); ok {
			if err := dir.walk(w, nextDepth); err != nil {
				return err
			}
		}
	}
	return nil
}

// Walk will recursively traverse the contents of this directory and invoke the given
// WalkFunc on each entry.
func (d *Directory) Walk(w WalkFunc) error {
	return d.walk(w, 0)
}

// GetPath returns this directory's path.
func (d *Directory) GetPath() string {
	return d.Path
}

// File is a Detectable implementation that represents a file.
type File struct {
	Path     string
	Fs       afero.Fs
	ext      string
	contents []byte
}

// DetectType will invoke the given detector on this file.
func (f *File) DetectType(d Detector, opts DetectOptions) (IACConfiguration, error) {
	return d.DetectFile(f, opts)
}

// Ext returns this file's extension.
func (f *File) Ext() string {
	if f.ext != "" {
		return f.ext
	}
	f.ext = filepath.Ext(f.Path)
	return f.ext
}

// Contents returns the contents of this file
func (f *File) Contents() ([]byte, error) {
	if f.contents != nil {
		return f.contents, nil
	}
	contents, err := afero.ReadFile(f.Fs, f.Path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", UnableToReadFile, err)
	}

	f.contents = contents
	return contents, nil
}

// GetPath returns this file's path.
func (f *File) GetPath() string {
	return f.Path
}
