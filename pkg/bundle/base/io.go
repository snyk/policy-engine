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

package base

import (
	"io"
)

type SourceType string

type WalkFilesFunc func(path string, f io.Reader) error

type Reader interface {
	WalkFiles(handler WalkFilesFunc) error
	Info() SourceInfo
	Manifest() (*Manifest, error)
}

type FileInfo struct {
	Path     string `json:"path"`
	Checksum string `json:"checksum"`
}

type SourceInfo struct {
	SourceType SourceType `json:"source_type"`
	FileInfo   FileInfo   `json:"file_info"`
}

type File struct {
	Raw  []byte
	Info FileInfo
}

type FileConsumer func(f File) error

type FileProducer interface {
	Produce(consumer FileConsumer) error
	Info() SourceInfo
}

type Writer interface {
	Write(bundle Bundle) error
}
