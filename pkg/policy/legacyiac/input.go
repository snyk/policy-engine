package legacyiac

import (
	"container/list"
	"strconv"
	"strings"
)

type ParsedMsg struct {
	ResourceID   string
	ResourceType string
	// Optional, replaced by defaultResourceNamespace if empty
	ResourceNamespace string
	Path              []interface{}
}

type Input interface {
	Raw() interface{}
	ParseMsg(msg string) ParsedMsg
}

type parsePathState int

const (
	inIdentifier parsePathState = iota
	inBracket
	inSingleQuote
	inDoubleQuote
	inEscape
	parsePathError
)

type stateStack struct {
	stack *list.List
}

func (s *stateStack) pop() parsePathState {
	state := s.stack.Front()
	if state == nil {
		return parsePathError
	}
	return s.stack.Remove(state).(parsePathState)
}

func (s *stateStack) push(state parsePathState) {
	s.stack.PushFront(state)
}

func (s *stateStack) peek() parsePathState {
	state := s.stack.Front()
	if state == nil {
		return parsePathError
	}
	return state.Value.(parsePathState)
}

func newStateStack(init parsePathState) *stateStack {
	stack := &stateStack{
		stack: list.New(),
	}
	stack.push(init)
	return stack
}

func parsePath(msg string) []interface{} {
	// Trim off 'input' path element if it exists
	msg = strings.TrimPrefix(msg, "input.")
	path := []interface{}{}
	buf := []rune{}
	consumeBuf := func() {
		s := string(buf)
		if s == "" {
			return
		}
		if i, err := strconv.Atoi(s); err == nil {
			path = append(path, i)
		} else {
			path = append(path, s)
		}
		buf = []rune{}
	}
	stack := newStateStack(inIdentifier)
	for _, char := range msg {
		state := stack.peek()
		if state == parsePathError {
			break
		}
		switch char {
		case '.':
			switch state {
			case inIdentifier:
				consumeBuf()
			case inEscape:
				buf = append(buf, char)
				stack.pop()
			default:
				buf = append(buf, char)
			}
		case '[':
			switch state {
			case inIdentifier, inBracket:
				consumeBuf()
				stack.push(inBracket)
			case inEscape:
				buf = append(buf, char)
				stack.pop()
			default:
				buf = append(buf, char)
			}
		case ']':
			switch state {
			case inIdentifier:
				stack.push(parsePathError)
			case inEscape:
				buf = append(buf, char)
				stack.pop()
			case inBracket:
				consumeBuf()
				stack.pop()
			default:
				buf = append(buf, char)
			}
		case '"':
			switch state {
			case inSingleQuote:
				buf = append(buf, char)
			case inEscape:
				buf = append(buf, char)
				stack.pop()
			case inDoubleQuote:
				consumeBuf()
				stack.pop()
			default:
				stack.push(inDoubleQuote)
			}
		case '\'':
			switch state {
			case inDoubleQuote:
				buf = append(buf, char)
			case inEscape:
				buf = append(buf, char)
				stack.pop()
			case inSingleQuote:
				consumeBuf()
				stack.pop()
			default:
				stack.push(inSingleQuote)
			}
		case '\\':
			switch state {
			case inEscape:
				buf = append(buf, char)
				stack.pop()
			default:
				stack.push(inEscape)
			}
		default:
			buf = append(buf, char)
		}
	}
	consumeBuf()
	return path
}
