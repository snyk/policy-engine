package funcs

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"io"

	"github.com/spf13/afero"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// MakeFileBase64Sha256Func constructs a function that is like Base64Sha256Func but reads the
// contents of a file rather than hashing a given literal string.
func MakeFileBase64Sha256Func(fsys afero.Fs, baseDir string) function.Function {
	return makeFileHashFunction(fsys, baseDir, sha256.New, base64.StdEncoding.EncodeToString)
}

func MakeFileBase64Sha512Func(fsys afero.Fs, baseDir string) function.Function {
	return makeFileHashFunction(fsys, baseDir, sha512.New, base64.StdEncoding.EncodeToString)
}

// MakeFileMd5Func constructs a function that is like Md5Func but reads the
// contents of a file rather than hashing a given literal string.
func MakeFileMd5Func(fsys afero.Fs, baseDir string) function.Function {
	return makeFileHashFunction(fsys, baseDir, md5.New, hex.EncodeToString)
}

// MakeFileSha1Func constructs a function that is like Sha1Func but reads the
// contents of a file rather than hashing a given literal string.
func MakeFileSha1Func(fsys afero.Fs, baseDir string) function.Function {
	return makeFileHashFunction(fsys, baseDir, sha1.New, hex.EncodeToString)
}

// MakeFileSha256Func constructs a function that is like Sha256Func but reads the
// contents of a file rather than hashing a given literal string.
func MakeFileSha256Func(fsys afero.Fs, baseDir string) function.Function {
	return makeFileHashFunction(fsys, baseDir, sha256.New, hex.EncodeToString)
}

// MakeFileSha512Func constructs a function that is like Sha512Func but reads the
// contents of a file rather than hashing a given literal string.
func MakeFileSha512Func(fsys afero.Fs, baseDir string) function.Function {
	return makeFileHashFunction(fsys, baseDir, sha512.New, hex.EncodeToString)
}

func makeFileHashFunction(fsys afero.Fs, baseDir string, hf func() hash.Hash, enc func([]byte) string) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{
				Name: "path",
				Type: cty.String,
			},
		},
		Type: function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, retType cty.Type) (ret cty.Value, err error) {
			path := args[0].AsString()
			f, err := openFile(fsys, baseDir, path)
			if err != nil {
				return cty.UnknownVal(cty.String), err
			}
			defer f.Close()

			h := hf()
			_, err = io.Copy(h, f)
			if err != nil {
				return cty.UnknownVal(cty.String), err
			}
			rv := enc(h.Sum(nil))
			return cty.StringVal(rv), nil
		},
	})
}
