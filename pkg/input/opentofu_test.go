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

package input_test

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/policy-engine/pkg/input"
)

func TestOpenTofuDetector(t *testing.T) {
	detector := &input.OpenTofuDetector{}

	t.Run("detects valid .tofu file", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		content := `resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}`
		afero.WriteFile(fs, "/test.tofu", []byte(content), 0644)

		f := &input.File{
			Path: "/test.tofu",
			Fs:   fs,
		}

		config, err := detector.DetectFile(f, input.DetectOptions{})
		assert.NoError(t, err)
		assert.NotNil(t, config)
		assert.Equal(t, input.OpenTofuHCL, config.Type())
	})

	t.Run("detects valid .tofu.json file", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		content := `{
  "resource": {
    "aws_s3_bucket": {
      "example": {
        "bucket": "my-bucket"
      }
    }
  }
}`
		afero.WriteFile(fs, "/test.tofu.json", []byte(content), 0644)

		f := &input.File{
			Path: "/test.tofu.json",
			Fs:   fs,
		}

		config, err := detector.DetectFile(f, input.DetectOptions{})
		assert.NoError(t, err)
		assert.NotNil(t, config)
		assert.Equal(t, input.OpenTofuHCL, config.Type())
	})

	t.Run("rejects file with wrong extension", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		content := `resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}`
		afero.WriteFile(fs, "/test.txt", []byte(content), 0644)

		f := &input.File{
			Path: "/test.txt",
			Fs:   fs,
		}

		config, err := detector.DetectFile(f, input.DetectOptions{})
		assert.ErrorIs(t, err, input.UnrecognizedFileExtension)
		assert.Nil(t, config)
	})

	t.Run("ignores extension when IgnoreExt is true", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		content := `resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}`
		afero.WriteFile(fs, "/test.txt", []byte(content), 0644)

		f := &input.File{
			Path: "/test.txt",
			Fs:   fs,
		}

		config, err := detector.DetectFile(f, input.DetectOptions{IgnoreExt: true})
		assert.NoError(t, err)
		assert.NotNil(t, config)
	})

	t.Run("detects directory with .tofu files", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		content := `resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}`
		fs.MkdirAll("/testdir", 0755)
		afero.WriteFile(fs, "/testdir/main.tofu", []byte(content), 0644)

		d := &input.Directory{
			Path: "/testdir",
			Fs:   fs,
		}

		config, err := detector.DetectDirectory(d, input.DetectOptions{})
		assert.NoError(t, err)
		assert.NotNil(t, config)
		assert.Equal(t, input.OpenTofuHCL, config.Type())
	})

	t.Run("returns nil for directory without .tofu files", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		content := `resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}`
		fs.MkdirAll("/testdir", 0755)
		afero.WriteFile(fs, "/testdir/main.txt", []byte(content), 0644)

		d := &input.Directory{
			Path: "/testdir",
			Fs:   fs,
		}

		config, err := detector.DetectDirectory(d, input.DetectOptions{})
		assert.NoError(t, err)
		assert.Nil(t, config)
	})
}