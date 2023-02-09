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
	Path     string
	Checksum string
}

type SourceInfo struct {
	SourceType SourceType
	FileInfo   FileInfo
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
