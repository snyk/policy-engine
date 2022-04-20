package data

import (
	"io"

	"github.com/open-policy-agent/opa/ast"
	"gopkg.in/yaml.v3"
)

type parser func(path string, reader io.Reader, consumer Consumer) error

func regoParser(path string, reader io.Reader, consumer Consumer) error {
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	module, err := ast.ParseModule(path, string(bytes))
	if err != nil {
		return err
	}
	return consumer.Module(path, module)
}

func documentParser(path string, reader io.Reader, consumer Consumer) error {
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	var document map[string]interface{}
	if err := yaml.Unmarshal(bytes, &document); err != nil {
		return err
	}
	return consumer.DataDocument(path, document)
}

var parsersByExtension = map[string]parser{
	".rego": regoParser,
	".yml":  documentParser,
	".yaml": documentParser,
	".json": documentParser,
}
