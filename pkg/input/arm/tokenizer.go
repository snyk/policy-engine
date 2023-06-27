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
	"unicode"
)

func tokenize(input string) ([]token, error) {
	var tokens []token
	t := &tokenizer{remaining: []rune(input)}
	for {
		tkn, err := t.next()
		if err != nil {
			return nil, err
		}
		if tkn == nil {
			return tokens, nil
		}
		tokens = append(tokens, tkn)
	}
}

type tokenizer struct {
	remaining []rune
}

func (t *tokenizer) peek() (rune, bool) {
	if len(t.remaining) == 0 {
		return 0, false
	}
	return t.remaining[0], true
}

func (t *tokenizer) pop() (rune, bool) {
	c, ok := t.peek()
	if !ok {
		return c, false
	}
	t.remaining = t.remaining[1:]
	return c, ok
}

func (t *tokenizer) next() (token, error) {
	// Discard any whitespace
	c1, ok := t.pop()
	for ok && unicode.IsSpace(c1) {
		c1, ok = t.pop()
	}

	// End of text
	if !ok {
		return nil, nil
	}

	switch c1 {
	case '(':
		return openParen{}, nil
	case ')':
		return closeParen{}, nil
	case ',':
		return comma{}, nil
	case '.':
		return dot{}, nil
	case '\'':
		// We are inside a string, parse it completely
		str := []rune{}
		for {
			c, ok := t.pop()
			if !ok {
				return nil, newTokenizerError(errors.New("expected ' to end string"))
			}
			if c == '\'' {
				// Could be end of string or an escaped '\', take a peek.
				c2, ok := t.peek()
				if ok && c2 == '\'' {
					t.pop()
					str = append(str, '\'')
				} else {
					return stringLiteral(string(str)), nil
				}
			} else {
				// A normal character inside a string, just add it.
				str = append(str, c)
			}
		}
	default:
		// if we reach here, the token is an identifier
		if validIdentifierStart(c1) {
			id := []rune{c1}
			for {
				// Keep adding valid characters to id while we can
				c, ok := t.peek()
				if ok && validIdentifierChar(c) {
					t.pop()
					id = append(id, c)
				} else {
					return identifier(string(id)), nil
				}
			}
		}

		return nil, newTokenizerError(errors.New("unexpected character"))
	}
}

func validIdentifierStart(c rune) bool {
	return unicode.IsLetter(c)
}

func validIdentifierChar(c rune) bool {
	return unicode.IsLetter(c) || unicode.IsDigit(c) || c == '_'
}

type token interface {
}

type openParen struct{}
type closeParen struct{}
type comma struct{}
type dot struct{}
type identifier string
type stringLiteral string

func newTokenizerError(underlying error) error {
	return Error{underlying: underlying, kind: TokenizerError}
}
