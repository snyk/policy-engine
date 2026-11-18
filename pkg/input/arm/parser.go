// © 2022-2023 Snyk Limited All rights reserved.
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

package arm

import (
	"errors"
	"fmt"
)

func parse(tokens []token) (expression, error) {
	p := &parser{remaining: tokens}
	return p.parse()
}

type parser struct {
	remaining []token
}

func (p *parser) parse() (expression, error) {
	tkn, ok := p.pop()
	if !ok {
		return nil, newParserError(errors.New("can't build expression from 0 tokens"))
	}

	// We may need to add support for more types (integer, bool, arrays and
	// objects) when we add support for more functions.
	//
	// When adding more types, please remember to update support for these types
	// in variables. See pkg/input/arm.go.
	//
	// https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-expressions
	if strToken, ok := tkn.(stringLiteral); ok {
		return stringLiteralExpr(strToken), nil
	}

	// Parse arrays
	if _, ok := tkn.(openBracket); ok {
		items, err := parseList(p, comma{}, closeBracket{}, func() (expression, error) {
			return p.parse()
		})
		if err != nil {
			return nil, err
		}
		return arrayExpr(items), nil
	}

	// If we reach here, we are building a function expression, because there are
	// no "direct" identifier dereferences in ARM template expressions. The
	// identifier is the function name.
	idToken, ok := tkn.(identifier)
	if !ok {
		return nil, newParserError(fmt.Errorf("expected token %#v to be an identifier", tkn))
	}

	// expect an open paren
	tkn, ok = p.pop()
	if !ok {
		return nil, newParserError(errors.New("expression cannot terminate with an identifier"))
	}
	if _, ok := tkn.(openParen); !ok {
		return nil, newParserError(fmt.Errorf("expected token %#v to be a paren", tkn))
	}
	if _, ok := p.peek(); !ok {
		return nil, newParserError(errors.New("expression cannot terminate with an open paren"))
	}

	var args []expression
	args, err := parseList(p, comma{}, closeParen{}, func() (expression, error) {
		return p.parse()
	})
	if err != nil {
		return nil, err
	}
	expr := functionExpr{name: string(idToken), args: args}
	return p.buildPropertyAccessExpression(expr)
}

func (p *parser) buildPropertyAccessExpression(expr expression) (expression, error) {
	identifiers, err := parsePairs(p, dot{}, func() (string, error) {
		if tkn, ok := p.pop(); ok {
			if id, ok := tkn.(identifier); ok {
				return string(id), nil
			} else {
				return "", newParserError(fmt.Errorf("expected token %#v to be an identifier", tkn))
			}
		} else {
			return "", newParserError(errors.New("expression cannot terminate with a dot"))
		}
	})
	if err != nil {
		return nil, err
	}
	return makePropertyExpr(expr, identifiers), nil
}

func (p *parser) peek() (token, bool) {
	if len(p.remaining) == 0 {
		return nil, false
	}
	return p.remaining[0], true
}

func (p *parser) pop() (token, bool) {
	if len(p.remaining) == 0 {
		return nil, false
	}
	tkn := p.remaining[0]
	p.remaining = p.remaining[1:]
	return tkn, true
}

func newParserError(underlying error) error {
	return Error{underlying: underlying, kind: ParserError}
}

// parsePairs parses ([leading][item])*
func parsePairs[T any](
	p *parser,
	leading token,
	parseItem func() (T, error),
) ([]T, error) {
	items := []T{}
	for {
		tkn, ok := p.peek()
		if !ok || tkn != leading {
			return items, nil
		}
		p.pop()
		item, err := parseItem()
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
}

// parseList parses [item]?([seperator][item])*[trailing]
// This is a possibly empty list, separated by separator (usually ',') and
// ended by trailing (think ')' or ']').
func parseList[T any](
	p *parser,
	separator token,
	trailing token,
	parseItem func() (T, error),
) ([]T, error) {
	tkn, ok := p.peek()
	if !ok {
		return nil, newParserError(errors.New("expected list to be closed"))
	}
	if tkn == trailing {
		p.pop()
		return nil, nil // Empty list
	}
	item0, err := parseItem()
	if err != nil {
		return nil, err
	}
	items := []T{item0}
	moreItems, err := parsePairs(p, comma{}, parseItem)
	if err != nil {
		return nil, err
	}
	items = append(items, moreItems...)
	tkn, ok = p.pop()
	if !ok || tkn != trailing {
		return nil, newParserError(fmt.Errorf("expected list to be closed with %#v", trailing))
	}
	return items, nil
}
