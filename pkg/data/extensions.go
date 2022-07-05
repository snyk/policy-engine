package data

import (
	"context"
	"fmt"
	"io"

	"github.com/open-policy-agent/opa/ast"
	"gopkg.in/yaml.v3"
)

type parser func(ctx context.Context, basePath string, path string, reader io.Reader, consumer Consumer) error

func regoParser(
	ctx context.Context,
	basePath string,
	path string,
	reader io.Reader,
	consumer Consumer,
) error {
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	module, err := ast.ParseModule(path, string(bytes))
	if err != nil {
		return err
	}
	return consumer.Module(ctx, path, module)
}

func documentParser(
	ctx context.Context,
	basePath string,
	path string,
	reader io.Reader,
	consumer Consumer,
) error {
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	var document interface{} // Array or object
	if err := yaml.Unmarshal(bytes, &document); err != nil {
		return err
	}
	prefix := dataDocumentPrefix(basePath, path)
	for i := len(prefix) - 1; i >= 0; i-- {
		document = map[string]interface{}{
			prefix[i]: document,
		}
	}
	// Must be an object at this point to conform to OPA API.
	switch doc := document.(type) {
	case map[string]interface{}:
		return consumer.DataDocument(ctx, path, doc)
	default:
		return fmt.Errorf("%s: Root data document needs to be object not array", path)
	}
}

var parsersByExtension = map[string]parser{
	".rego": regoParser,
	".yml":  documentParser,
	".yaml": documentParser,
	".json": documentParser,
}
