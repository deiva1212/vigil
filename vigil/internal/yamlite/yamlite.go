// Package yamlite is a small, dependency-free YAML subset parser that covers
// what Sigma rules and Vigil config files use: block maps, block lists,
// lists of maps, inline [a, b] lists, quoted scalars, comments, and | / >
// block scalars. All scalars are returned as strings; nulls as nil.
//
// It deliberately does not support anchors, tags, or flow maps with content.
// If you need full YAML, swap in gopkg.in/yaml.v3 — the output shape
// (map[string]any / []any / string) is compatible.
package yamlite

import (
	"fmt"
	"strings"
)

type line struct {
	indent int
	text   string // trimmed, comment stripped
	raw    string // original line (for block scalars)
	num    int
}

type parser struct {
	lines []line
	pos   int
}

// Parse parses the first YAML document in src.
func Parse(src string) (any, error) {
	docs, err := ParseAll(src)
	if err != nil {
		return nil, err
	}
	if len(docs) == 0 {
		return map[string]any{}, nil
	}
	return docs[0], nil
}

// ParseAll parses every document separated by "---".
func ParseAll(src string) ([]any, error) {
	src = strings.ReplaceAll(src, "\r\n", "\n")
	src = strings.ReplaceAll(src, "\t", "    ")
	var docs []any
	var cur []string
	flush := func() error {
		if len(cur) == 0 {
			return nil
		}
		v, err := parseDoc(strings.Join(cur, "\n"))
		if err != nil {
			return err
		}
		if v != nil {
			docs = append(docs, v)
		}
		cur = nil
		return nil
	}
	for _, l := range strings.Split(src, "\n") {
		if strings.TrimRight(l, " ") == "---" {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		cur = append(cur, l)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return docs, nil
}

func parseDoc(src string) (any, error) {
	p := &parser{}
	for i, raw := range strings.Split(src, "\n") {
		t := stripComment(raw)
		if strings.TrimSpace(t) == "" {
			// keep blank lines as markers only for block scalars
			p.lines = append(p.lines, line{indent: -1, text: "", raw: raw, num: i + 1})
			continue
		}
		ind := len(t) - len(strings.TrimLeft(t, " "))
		p.lines = append(p.lines, line{indent: ind, text: strings.TrimSpace(t), raw: raw, num: i + 1})
	}
	p.skipBlank()
	if p.pos >= len(p.lines) {
		return nil, nil
	}
	return p.parseBlock(p.lines[p.pos].indent)
}

func (p *parser) skipBlank() {
	for p.pos < len(p.lines) && p.lines[p.pos].indent < 0 {
		p.pos++
	}
}

func (p *parser) peek() (line, bool) {
	p.skipBlank()
	if p.pos >= len(p.lines) {
		return line{}, false
	}
	return p.lines[p.pos], true
}

func isListItem(t string) bool { return t == "-" || strings.HasPrefix(t, "- ") }

func (p *parser) parseBlock(indent int) (any, error) {
	l, ok := p.peek()
	if !ok {
		return nil, nil
	}
	if isListItem(l.text) {
		return p.parseList(indent)
	}
	if _, _, isKV := splitKey(l.text); isKV {
		return p.parseMap(indent)
	}
	// single scalar (possibly multi-line plain scalar)
	var parts []string
	for {
		l, ok := p.peek()
		if !ok || l.indent < indent {
			break
		}
		parts = append(parts, l.text)
		p.pos++
	}
	return scalar(strings.Join(parts, " ")), nil
}

func (p *parser) parseMap(indent int) (map[string]any, error) {
	m := map[string]any{}
	for {
		l, ok := p.peek()
		if !ok || l.indent < indent {
			return m, nil
		}
		if l.indent > indent {
			return nil, fmt.Errorf("yaml line %d: unexpected indentation", l.num)
		}
		if isListItem(l.text) {
			return m, nil // list at same indent belongs to the parent key
		}
		key, rest, isKV := splitKey(l.text)
		if !isKV {
			return nil, fmt.Errorf("yaml line %d: expected 'key: value', got %q", l.num, l.text)
		}
		key = unquote(key)
		p.pos++
		switch {
		case rest == "|" || rest == "|-" || rest == ">" || rest == ">-" || rest == "|+" || rest == ">+":
			m[key] = p.blockScalar(indent, rest[0] == '>')
		case rest == "":
			nl, ok := p.peek()
			if !ok {
				m[key] = nil
			} else if nl.indent > indent {
				v, err := p.parseBlock(nl.indent)
				if err != nil {
					return nil, err
				}
				m[key] = v
			} else if nl.indent == indent && isListItem(nl.text) {
				v, err := p.parseList(indent)
				if err != nil {
					return nil, err
				}
				m[key] = v
			} else {
				m[key] = nil
			}
		default:
			m[key] = scalar(rest)
		}
	}
}

func (p *parser) parseList(indent int) ([]any, error) {
	out := []any{}
	for {
		l, ok := p.peek()
		if !ok || l.indent != indent || !isListItem(l.text) {
			return out, nil
		}
		content := strings.TrimSpace(strings.TrimPrefix(l.text, "-"))
		if content == "" {
			p.pos++
			nl, ok := p.peek()
			if ok && nl.indent > indent {
				v, err := p.parseBlock(nl.indent)
				if err != nil {
					return nil, err
				}
				out = append(out, v)
			} else {
				out = append(out, nil)
			}
			continue
		}
		if _, _, isKV := splitKey(content); isKV && !strings.HasPrefix(content, "[") && !strings.HasPrefix(content, "\"") && !strings.HasPrefix(content, "'") {
			// "- key: value" starts an inline map; rewrite this line in place
			off := strings.Index(l.text, content)
			p.lines[p.pos] = line{indent: indent + off, text: content, raw: l.raw, num: l.num}
			v, err := p.parseMap(indent + off)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}
		p.pos++
		out = append(out, scalar(content))
	}
}

func (p *parser) blockScalar(parentIndent int, folded bool) string {
	var parts []string
	blockIndent := -1
	for p.pos < len(p.lines) {
		l := p.lines[p.pos]
		if l.indent >= 0 && l.indent <= parentIndent {
			break
		}
		if l.indent < 0 {
			parts = append(parts, "")
			p.pos++
			continue
		}
		raw := l.raw
		ri := len(raw) - len(strings.TrimLeft(raw, " "))
		if blockIndent < 0 {
			blockIndent = ri
		}
		if ri >= blockIndent {
			raw = raw[blockIndent:]
		}
		parts = append(parts, strings.TrimRight(raw, " "))
		p.pos++
	}
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	if folded {
		return strings.Join(parts, " ")
	}
	return strings.Join(parts, "\n")
}

// splitKey finds the "key: value" separator outside quotes/brackets.
func splitKey(t string) (string, string, bool) {
	inS, inD, depth := false, false, 0
	for i := 0; i < len(t); i++ {
		c := t[i]
		switch {
		case c == '\'' && !inD && (inS || opens(t, i)):
			inS = !inS
		case c == '"' && !inS && (inD || opens(t, i)):
			inD = !inD
		case (c == '[' || c == '{') && !inS && !inD:
			depth++
		case (c == ']' || c == '}') && !inS && !inD:
			depth--
		case c == ':' && !inS && !inD && depth == 0:
			if i == len(t)-1 {
				return strings.TrimSpace(t[:i]), "", true
			}
			if t[i+1] == ' ' {
				return strings.TrimSpace(t[:i]), strings.TrimSpace(t[i+1:]), true
			}
		}
	}
	return "", "", false
}

func stripComment(s string) string {
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inD && (inS || opens(s, i)):
			inS = !inS
		case c == '"' && !inS && (inD || opens(s, i)):
			inD = !inD
		case c == '#' && !inS && !inD:
			if i == 0 || s[i-1] == ' ' {
				return strings.TrimRight(s[:i], " ")
			}
		}
	}
	return strings.TrimRight(s, " ")
}

func scalar(s string) any {
	s = strings.TrimSpace(s)
	switch s {
	case "", "~", "null", "Null", "NULL":
		return nil
	case "[]":
		return []any{}
	case "{}":
		return map[string]any{}
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		inner := s[1 : len(s)-1]
		var out []any
		for _, part := range splitComma(inner) {
			if strings.TrimSpace(part) == "" {
				continue
			}
			out = append(out, scalar(part))
		}
		if out == nil {
			out = []any{}
		}
		return out
	}
	return unquote(s)
}

func splitComma(s string) []string {
	var out []string
	inS, inD, start := false, false, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\'' && !inD:
			inS = !inS
		case c == '"' && !inS:
			inD = !inD
		case c == ',' && !inS && !inD:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		in := s[1 : len(s)-1]
		var b strings.Builder
		for i := 0; i < len(in); i++ {
			if in[i] == '\\' && i+1 < len(in) {
				i++
				switch in[i] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				case '"':
					b.WriteByte('"')
				case '\\':
					b.WriteByte('\\')
				default:
					b.WriteByte('\\')
					b.WriteByte(in[i])
				}
				continue
			}
			b.WriteByte(in[i])
		}
		return b.String()
	}
	return s
}

// opens reports whether a quote at position i can start a quoted scalar,
// so apostrophes inside plain words ("user's") are not treated as quotes.
func opens(s string, i int) bool {
	if i == 0 {
		return true
	}
	return strings.ContainsRune(" :[,{-", rune(s[i-1]))
}
