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
	// https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-expressions
	if strToken, ok := tkn.(stringLiteral); ok {
		return stringLiteralExpr(strToken), nil
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
	for {
		// In the first iteration, we've just peeked successfully. In all subsequent
		// iterations, we'd have broken out of the loop if we had exhausted all
		// tokens.
		tkn, _ := p.peek()
		if _, ok := tkn.(closeParen); ok {
			p.pop() // pop the close paren
			expr := functionExpr{name: string(idToken), args: args}
			tkn, ok := p.peek()
			if !ok {
				return expr, nil
			}
			if _, ok := tkn.(dot); ok {
				return p.buildPropertyAccessExpression(expr)
			}
			return expr, nil
		}

		// There is a comma between args, so not before the first arg
		if len(args) > 0 {
			// We can't reach here if we have exhausted all tokens above
			tkn, _ := p.peek()
			if _, ok := tkn.(comma); !ok {
				return nil, newParserError(fmt.Errorf("expected token %#v to be a comma", tkn))
			}
			p.pop() // pop the comma
		}

		nextArg, err := p.parse()
		if err != nil {
			return nil, err
		}
		args = append(args, nextArg)
	}
}

func (p *parser) buildPropertyAccessExpression(expr expression) (expression, error) {
	// we only enter this function from parse() if we peeked at a dot, so we know
	// it gets past here at least once, and so always builds a real property
	// access expression.
	tkn, ok := p.peek()
	if !ok {
		return expr, nil
	}
	if _, ok := tkn.(dot); !ok {
		return expr, nil
	}

	p.pop() // pop the dot
	tkn, ok = p.pop()
	if !ok {
		return nil, newParserError(errors.New("expression cannot terminate with a dot"))
	}
	nextPropChainElement, ok := tkn.(identifier)
	if !ok {
		return nil, newParserError(fmt.Errorf("expected token %#v to be an identifier", tkn))
	}
	expr = propertyExpr{obj: expr, property: string(nextPropChainElement)}
	return p.buildPropertyAccessExpression(expr)
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
