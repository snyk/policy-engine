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
