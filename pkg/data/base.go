package data

import (
	"context"

	"github.com/open-policy-agent/opa/ast"
)

type Consumer interface {
	Module(ctx context.Context, path string, module *ast.Module) error
	DataDocument(ctx context.Context, path string, document map[string]interface{}) error
}

type Provider func(context.Context, Consumer) error
