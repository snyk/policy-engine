package legacyiac

import (
	"strconv"
	"strings"
)

type ParsedMsg struct {
	ResourceID   string
	ResourceType string
	Path         []interface{}
}

type Input interface {
	Raw() interface{}
	ParseMsg(msg string) ParsedMsg
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
	var inBracket bool
	for _, char := range msg {
		switch char {
		case '.':
			if !inBracket {
				consumeBuf()
			} else {
				buf = append(buf, char)
			}
		case '[':
			consumeBuf()
			inBracket = true
		case ']':
			consumeBuf()
			inBracket = false
		default:
			buf = append(buf, char)
		}
	}
	consumeBuf()
	return path
}
