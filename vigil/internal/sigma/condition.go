package sigma

import (
	"fmt"
	"path"
	"strings"

	"github.com/vigil-siem/vigil/internal/common"
)

// node is a compiled condition expression.
type node interface {
	eval(r *Rule, e *common.Event) bool
}

type andNode struct{ l, r node }
type orNode struct{ l, r node }
type notNode struct{ n node }
type selNode struct{ name string }
type ofNode struct {
	all   bool
	names []string
}

func (n andNode) eval(r *Rule, e *common.Event) bool { return n.l.eval(r, e) && n.r.eval(r, e) }
func (n orNode) eval(r *Rule, e *common.Event) bool  { return n.l.eval(r, e) || n.r.eval(r, e) }
func (n notNode) eval(r *Rule, e *common.Event) bool { return !n.n.eval(r, e) }
func (n selNode) eval(r *Rule, e *common.Event) bool {
	s := r.selections[n.name]
	return s != nil && s.match(e)
}
func (n ofNode) eval(r *Rule, e *common.Event) bool {
	for _, name := range n.names {
		m := r.selections[name].match(e)
		if n.all && !m {
			return false
		}
		if !n.all && m {
			return true
		}
	}
	return n.all
}

type condParser struct {
	toks  []string
	pos   int
	names []string
}

func tokenize(s string) []string {
	var toks []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for _, c := range s {
		switch c {
		case '(', ')':
			flush()
			toks = append(toks, string(c))
		case ' ', '\t', '\n':
			flush()
		default:
			cur.WriteRune(c)
		}
	}
	flush()
	return toks
}

func parseCondition(cond string, names []string) (node, error) {
	if strings.Contains(cond, "|") {
		return nil, fmt.Errorf("legacy aggregation expressions (|) are not supported; use a correlation rule")
	}
	p := &condParser{toks: tokenize(cond), names: names}
	if len(p.toks) == 0 {
		return nil, fmt.Errorf("empty condition")
	}
	n, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("unexpected token %q", p.toks[p.pos])
	}
	return n, nil
}

func (p *condParser) peek() string {
	if p.pos < len(p.toks) {
		return strings.ToLower(p.toks[p.pos])
	}
	return ""
}

func (p *condParser) parseOr() (node, error) {
	l, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek() == "or" {
		p.pos++
		r, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		l = orNode{l, r}
	}
	return l, nil
}

func (p *condParser) parseAnd() (node, error) {
	l, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.peek() == "and" {
		p.pos++
		r, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		l = andNode{l, r}
	}
	return l, nil
}

func (p *condParser) parseNot() (node, error) {
	if p.peek() == "not" {
		p.pos++
		n, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return notNode{n}, nil
	}
	return p.parsePrimary()
}

func (p *condParser) parsePrimary() (node, error) {
	t := p.peek()
	switch {
	case t == "":
		return nil, fmt.Errorf("unexpected end of condition")
	case t == "(":
		p.pos++
		n, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("missing )")
		}
		p.pos++
		return n, nil
	case t == "1" || t == "all" || t == "any":
		if p.pos+2 < len(p.toks) && strings.ToLower(p.toks[p.pos+1]) == "of" {
			all := t == "all"
			pattern := p.toks[p.pos+2]
			p.pos += 3
			var matched []string
			for _, n := range p.names {
				if pattern == "them" {
					if strings.HasPrefix(n, "_") {
						continue
					}
					matched = append(matched, n)
				} else if ok, _ := path.Match(pattern, n); ok {
					matched = append(matched, n)
				}
			}
			if len(matched) == 0 {
				return nil, fmt.Errorf("no selections match %q", pattern)
			}
			return ofNode{all: all, names: matched}, nil
		}
	}
	name := p.toks[p.pos]
	found := false
	for _, n := range p.names {
		if n == name {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("unknown selection %q", name)
	}
	p.pos++
	return selNode{name}, nil
}
