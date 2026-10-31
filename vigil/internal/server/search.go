package server

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/vigil-siem/vigil/internal/common"
)

// Query language for event search (all terms ANDed):
//
//	ssh                       free text, case-insensitive, anywhere in the event
//	"failed password"         quoted phrase
//	source.ip:1.2.3.4         field equals (case-insensitive)
//	user.name:adm*            wildcard
//	-user.name:root           negation (also works for free text: -cron)
//	http.response.status_code>=400   numeric comparison (>, >=, <, <=)
//	category:fim  agent:web-01  source:/var/log/auth.log   event envelope fields
func ParseQuery(q string) func(*common.Event) bool {
	terms := splitQuery(q)
	var preds []func(*common.Event) bool
	for _, t := range terms {
		neg := false
		if strings.HasPrefix(t, "-") && len(t) > 1 {
			neg, t = true, t[1:]
		}
		p := termPredicate(t)
		if neg {
			inner := p
			p = func(e *common.Event) bool { return !inner(e) }
		}
		preds = append(preds, p)
	}
	return func(e *common.Event) bool {
		for _, p := range preds {
			if !p(e) {
				return false
			}
		}
		return true
	}
}

var reCmp = regexp.MustCompile(`^([\w.@-]+)(>=|<=|>|<)(-?[\d.]+)$`)

func termPredicate(t string) func(*common.Event) bool {
	if m := reCmp.FindStringSubmatch(t); m != nil {
		field, op := m[1], m[2]
		want, _ := strconv.ParseFloat(m[3], 64)
		return func(e *common.Event) bool {
			got, err := strconv.ParseFloat(eventField(e, field), 64)
			if err != nil {
				return false
			}
			switch op {
			case ">":
				return got > want
			case ">=":
				return got >= want
			case "<":
				return got < want
			}
			return got <= want
		}
	}
	if field, val, ok := strings.Cut(t, ":"); ok && field != "" && !strings.Contains(field, "/") && !strings.HasPrefix(field, "\"") {
		val = strings.Trim(val, "\"")
		match := wildcard(val)
		return func(e *common.Event) bool { return match(eventField(e, field)) }
	}
	needle := strings.ToLower(strings.Trim(t, "\""))
	return func(e *common.Event) bool {
		if strings.Contains(strings.ToLower(e.Raw), needle) {
			return true
		}
		for k, v := range e.Fields {
			if strings.Contains(strings.ToLower(v), needle) || strings.Contains(strings.ToLower(k), needle) {
				return true
			}
		}
		return strings.Contains(strings.ToLower(e.Hostname), needle)
	}
}

func eventField(e *common.Event, f string) string {
	switch f {
	case "agent", "host", "hostname":
		return e.Hostname
	case "agent_id":
		return e.AgentID
	case "category":
		return e.Category
	case "source":
		return e.Source
	case "id":
		return e.ID
	}
	return e.Fields[f]
}

func wildcard(p string) func(string) bool {
	lp := strings.ToLower(p)
	if !strings.ContainsAny(p, "*?") {
		return func(s string) bool { return strings.ToLower(s) == lp }
	}
	re := regexp.MustCompile("(?i)^" + strings.NewReplacer(`\*`, ".*", `\?`, ".").Replace(regexp.QuoteMeta(p)) + "$")
	return re.MatchString
}

func splitQuery(q string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for _, c := range q {
		switch {
		case c == '"':
			inQ = !inQ
			cur.WriteRune(c)
		case (c == ' ' || c == '\t') && !inQ:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
