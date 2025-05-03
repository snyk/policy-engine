package funcs

import (
	"github.com/snyk/policy-engine/pkg/internal/tofu/lang"
	"github.com/spf13/afero"
	"github.com/zclconf/go-cty/cty/function"
)

func Override(fsys afero.Fs, scope lang.Scope) map[string]function.Function {
	base := scope.Functions()
	// filesystem functions
	base["abspath"] = MakeAbsPathFunc(fsys, scope.BaseDir)
	base["dirname"] = DirnameFunc
	base["pathexpand"] = MakePathExpandFunc(fsys)
	base["basename"] = BasenameFunc
	base["file"] = MakeFileFunc(fsys, scope.BaseDir, false)
	base["fileexists"] = MakeFileExistsFunc(fsys, scope.BaseDir)
	base["fileset"] = MakeFileSetFunc(fsys, scope.BaseDir)
	base["filebase64"] = MakeFileFunc(fsys, scope.BaseDir, true)
	base["templatefile"] = MakeTemplateFileFunc(fsys, scope.BaseDir, func() map[string]function.Function {
		return Override(fsys, scope)
	})
	// crypto functions
	base["filebase64sha256"] = MakeFileBase64Sha256Func(fsys, scope.BaseDir)
	base["filebase64sha512"] = MakeFileBase64Sha512Func(fsys, scope.BaseDir)
	base["filemd5"] = MakeFileMd5Func(fsys, scope.BaseDir)
	base["filesha1"] = MakeFileSha1Func(fsys, scope.BaseDir)
	base["filesha256"] = MakeFileSha256Func(fsys, scope.BaseDir)
	base["filesha512"] = MakeFileSha512Func(fsys, scope.BaseDir)
	return base
}
