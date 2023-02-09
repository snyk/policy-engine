// Copyright 2022 Snyk Ltd
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

package engine

import (
	"context"

	"github.com/open-policy-agent/opa/ast"
	"github.com/snyk/policy-engine/pkg/interfacetricks"
)

// PolicyConsumer is an implementation of the data.Consumer interface that stores
// parsed modules, policies, and documents in-memory.
type PolicyConsumer struct {
	Modules      map[string]*ast.Module
	Document     map[string]interface{}
	NumDocuments int
}

func NewPolicyConsumer() *PolicyConsumer {
	return &PolicyConsumer{
		Modules:      map[string]*ast.Module{},
		Document:     map[string]interface{}{},
		NumDocuments: 0,
	}
}

func (c *PolicyConsumer) Module(
	ctx context.Context,
	path string,
	module *ast.Module,
) error {
	c.Modules[path] = module
	return nil
}

func (c *PolicyConsumer) DataDocument(
	_ context.Context,
	path string,
	document map[string]interface{},
) error {
	c.Document = interfacetricks.MergeObjects(c.Document, document)
	c.NumDocuments += 1
	return nil
}
