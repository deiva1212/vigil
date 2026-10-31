package sigma

import (
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/vigil-siem/vigil/internal/common"
)

// FieldAliases maps common Sigma / Sysmon / auditd field names to Vigil's
// ECS-style taxonomy so community rules work without rewriting.
var FieldAliases = map[string]string{
	"image":             "process.executable",
	"commandline":       "process.command_line",
	"parentimage":       "process.parent.executable",
	"parentcommandline": "process.parent.command_line",
	"processid":         "process.pid",
	"user":              "user.name",
	"username":          "user.name",
	"targetusername":    "user.target",
	"targetfilename":    "file.path",
	"filename":          "file.path",
	"sourceip":          "source.ip",
	"src_ip":            "source.ip",
	"ipaddress":         "source.ip",
	"destinationip":     "destination.ip",
	"dst_ip":            "destination.ip",
	"destinationport":   "destination.port",
	"dst_port":          "destination.port",
	"sourceport":        "source.port",
	"hostname":          "host.name",
	"computer":          "host.name",
	"eventid":           "event.code",
	"exe":               "process.executable",
	"comm":              "process.name",
	"type":              "auditd.type",
	"msg":               "message",
	"service":           "log.service",
}

// lookup finds a field value on an event (exact, alias, case-insensitive).
func lookup(e *common.Event, field string) (string, bool) {
	if v, ok := e.Fields[field]; ok {
		return v, true
	}
	lf := strings.ToLower(field)
	if a, ok := FieldAliases[lf]; ok {
		if v, ok := e.Fields[a]; ok {
			return v, true
		}
	}
	for k, v := range e.Fields {
		if strings.EqualFold(k, field) {
			return v, true
		}
	}
	switch lf {
	case "message", "raw":
		if e.Raw != "" {
			return e.Raw, true
		}
	case "host.name":
		return e.Hostname, e.Hostname != ""
	case "event.category":
		return e.Category, true
	}
	return "", false
}

// ---------------------------------------------------------------- selections

type selection struct {
	groups   [][]*fieldMatcher // OR of groups; each group is AND of field matchers
	keywords []valueMatcher    // OR of keyword matchers against raw/message
	allKw    bool
}

type fieldMatcher struct {
	field    string
	matchers []valueMatcher // OR unless all
	all      bool
	exists   *bool
	nullOnly bool
}

type valueMatcher func(v string) bool

func compileSelection(v any) (*selection, error) {
	s := &selection{}
	switch x := v.(type) {
	case map[string]any:
		g, err := compileGroup(x)
		if err != nil {
			return nil, err
		}
		s.groups = [][]*fieldMatcher{g}
	case []any:
		for _, item := range x {
			switch it := item.(type) {
			case map[string]any:
				g, err := compileGroup(it)
				if err != nil {
					return nil, err
				}
				s.groups = append(s.groups, g)
			default:
				m, err := compileValue(str(it), []string{"contains"})
				if err != nil {
					return nil, err
				}
				s.keywords = append(s.keywords, m)
			}
		}
	case string:
		m, err := compileValue(x, []string{"contains"})
		if err != nil {
			return nil, err
		}
		s.keywords = append(s.keywords, m)
	default:
		return nil, fmt.Errorf("unsupported selection type %T", v)
	}
	return s, nil
}

func compileGroup(m map[string]any) ([]*fieldMatcher, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []*fieldMatcher
	for _, key := range keys {
		parts := strings.Split(key, "|")
		fm := &fieldMatcher{field: parts[0]}
		var mods []string
		for _, p := range parts[1:] {
			p = strings.ToLower(strings.TrimSpace(p))
			if p == "all" {
				fm.all = true
				continue
			}
			mods = append(mods, p)
		}
		val := m[key]
		if contains(mods, "exists") {
			b := strings.EqualFold(str(val), "true") || str(val) == "yes"
			fm.exists = &b
			out = append(out, fm)
			continue
		}
		var vals []any
		switch vv := val.(type) {
		case []any:
			vals = vv
		default:
			vals = []any{vv}
		}
		for _, one := range vals {
			if one == nil {
				fm.nullOnly = true
				continue
			}
			vm, err := compileValue(str(one), mods)
			if err != nil {
				return nil, fmt.Errorf("field %s: %w", key, err)
			}
			fm.matchers = append(fm.matchers, vm)
		}
		out = append(out, fm)
	}
	return out, nil
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// compileValue builds a matcher for one Sigma value + modifier chain.
func compileValue(val string, mods []string) (valueMatcher, error) {
	// value transformations first
	vals := []string{val}
	for _, m := range mods {
		switch m {
		case "base64":
			vals = []string{base64.StdEncoding.EncodeToString([]byte(val))}
		case "base64offset":
			var out []string
			for i := 0; i < 3; i++ {
				enc := base64.StdEncoding.EncodeToString(append(make([]byte, i), []byte(val)...))
				start := []int{0, 2, 3}[i]
				end := len(enc) - []int{0, 3, 2}[(len(val)+i)%3]
				if start < end {
					out = append(out, enc[start:end])
				}
			}
			vals = out
		case "windash":
			var out []string
			for _, v := range vals {
				out = append(out, v)
				if strings.Contains(v, "-") {
					out = append(out, strings.ReplaceAll(v, "-", "/"))
				}
				if strings.Contains(v, "/") {
					out = append(out, strings.ReplaceAll(v, "/", "-"))
				}
			}
			vals = out
		}
	}

	var ms []valueMatcher
	for _, v := range vals {
		m, err := compileOne(v, mods)
		if err != nil {
			return nil, err
		}
		ms = append(ms, m)
	}
	if len(ms) == 1 {
		return ms[0], nil
	}
	return func(s string) bool {
		for _, m := range ms {
			if m(s) {
				return true
			}
		}
		return false
	}, nil
}

func compileOne(v string, mods []string) (valueMatcher, error) {
	op := "equals"
	caseSensitive := false
	for _, m := range mods {
		switch m {
		case "contains", "startswith", "endswith", "re", "cidr", "lt", "lte", "gt", "gte":
			op = m
		case "cased":
			caseSensitive = true
		case "i", "m", "s", "base64", "base64offset", "windash", "utf16le", "utf16be", "wide":
		default:
			return nil, fmt.Errorf("unsupported modifier %q", m)
		}
	}
	switch op {
	case "re":
		flags := ""
		if contains(mods, "i") {
			flags += "i"
		}
		if contains(mods, "m") {
			flags += "m"
		}
		if contains(mods, "s") {
			flags += "s"
		}
		if flags != "" {
			v = "(?" + flags + ")" + v
		}
		re, err := regexp.Compile(v)
		if err != nil {
			return nil, err
		}
		return re.MatchString, nil
	case "cidr":
		_, n, err := net.ParseCIDR(v)
		if err != nil {
			return nil, err
		}
		return func(s string) bool {
			ip := net.ParseIP(strings.TrimSpace(s))
			return ip != nil && n.Contains(ip)
		}, nil
	case "lt", "lte", "gt", "gte":
		want, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return nil, fmt.Errorf("numeric modifier needs a number: %q", v)
		}
		return func(s string) bool {
			got, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
			if err != nil {
				return false
			}
			switch op {
			case "lt":
				return got < want
			case "lte":
				return got <= want
			case "gt":
				return got > want
			}
			return got >= want
		}, nil
	}

	// string ops with Sigma wildcard support (* and ?, escaped with \)
	pattern := v
	switch op {
	case "contains":
		pattern = "*" + v + "*"
	case "startswith":
		pattern = v + "*"
	case "endswith":
		pattern = "*" + v
	}
	if !hasWildcard(pattern) {
		lit := unescape(pattern)
		if caseSensitive {
			return func(s string) bool { return s == lit }, nil
		}
		return func(s string) bool { return strings.EqualFold(s, lit) }, nil
	}
	// fast paths for pure contains / prefix / suffix
	inner := pattern
	if strings.HasPrefix(inner, "*") && strings.HasSuffix(inner, "*") && len(inner) >= 2 && !hasWildcard(inner[1:len(inner)-1]) {
		lit := unescape(inner[1 : len(inner)-1])
		if caseSensitive {
			return func(s string) bool { return strings.Contains(s, lit) }, nil
		}
		ll := strings.ToLower(lit)
		return func(s string) bool { return strings.Contains(strings.ToLower(s), ll) }, nil
	}
	re, err := regexp.Compile(globToRegex(pattern, !caseSensitive))
	if err != nil {
		return nil, err
	}
	return re.MatchString, nil
}

func hasWildcard(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == '*' || s[i] == '?' {
			return true
		}
	}
	return false
}

func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '*' || s[i+1] == '?' || s[i+1] == '\\') {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func globToRegex(p string, ci bool) string {
	var b strings.Builder
	if ci {
		b.WriteString("(?is)")
	} else {
		b.WriteString("(?s)")
	}
	b.WriteString("^")
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c == '\\' && i+1 < len(p) && (p[i+1] == '*' || p[i+1] == '?' || p[i+1] == '\\'):
			i++
			b.WriteString(regexp.QuoteMeta(string(p[i])))
		case c == '*':
			b.WriteString(".*")
		case c == '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return b.String()
}

func (s *selection) match(e *common.Event) bool {
	if len(s.keywords) > 0 {
		hay := e.Raw
		if msg, ok := e.Fields["message"]; ok && msg != hay {
			hay = hay + "\n" + msg
		}
		for _, k := range s.keywords {
			if k(hay) {
				return true
			}
		}
		if len(s.groups) == 0 {
			return false
		}
	}
	for _, g := range s.groups {
		ok := true
		for _, fm := range g {
			if !fm.match(e) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func (fm *fieldMatcher) match(e *common.Event) bool {
	v, found := lookup(e, fm.field)
	if fm.exists != nil {
		return found == *fm.exists
	}
	if !found || v == "" {
		return fm.nullOnly
	}
	if len(fm.matchers) == 0 {
		return false
	}
	if fm.all {
		for _, m := range fm.matchers {
			if !m(v) {
				return false
			}
		}
		return true
	}
	for _, m := range fm.matchers {
		if m(v) {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------- rule matching

// Matches reports whether the event satisfies the rule's logsource and condition.
func (r *Rule) Matches(e *common.Event) bool {
	if r.IsCorrelation() || r.condition == nil || !r.Enabled {
		return false
	}
	if !r.logsourceMatches(e) {
		return false
	}
	return r.condition.eval(r, e)
}

// Sigma logsource categories mapped to Vigil event categories.
var categoryMap = map[string]string{
	"process_creation":    "process",
	"process_termination": "process",
	"file_event":          "fim",
	"file_change":         "fim",
	"file_delete":         "fim",
	"file_rename":         "fim",
	"network_connection":  "network",
	"firewall":            "log",
	"webserver":           "log",
	"authentication":      "log",
	"sca":                 "sca",
	"vulnerability":       "vulnerability",
}

func (r *Rule) logsourceMatches(e *common.Event) bool {
	ls := r.Logsource
	if ls.Product != "" {
		if osType, ok := e.Fields["os.type"]; ok && !strings.EqualFold(osType, ls.Product) {
			return false
		}
	}
	if ls.Category != "" {
		want := ls.Category
		if m, ok := categoryMap[want]; ok {
			want = m
		}
		if !strings.EqualFold(e.Category, want) {
			return false
		}
	}
	if ls.Service != "" {
		svc := e.Fields["log.service"]
		if svc == "" {
			return true // unknown service: let detection decide
		}
		if !strings.EqualFold(svc, ls.Service) && !(ls.Service == "auth" && (svc == "sshd" || svc == "sudo" || svc == "su" || svc == "login" || svc == "useradd" || svc == "passwd" || svc == "groupadd" || svc == "usermod" || svc == "userdel")) {
			return false
		}
	}
	return true
}
