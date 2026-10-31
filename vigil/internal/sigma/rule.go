// Package sigma implements a Sigma rule parser and matcher.
//
// Supported:
//   - detection selections as maps (AND), lists of maps (OR), keyword lists
//   - modifiers: contains, startswith, endswith, re, all, cidr, exists,
//     lt, lte, gt, gte, windash, base64 (exact), i (case-insensitive regex)
//   - wildcards * and ? in plain values, null values
//   - conditions: and, or, not, parentheses, "1 of x*", "all of x*",
//     "1 of them", "all of them", "any of"
//   - correlation rules: event_count, value_count (Sigma v2 format)
//   - Vigil extensions: `response:` (automatic active response) and
//     `compliance:` (explicit PCI/HIPAA/GDPR/NIST mappings)
package sigma

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vigil-siem/vigil/internal/yamlite"
)

// Rule is a compiled Sigma detection or correlation rule.
type Rule struct {
	ID             string
	Name           string
	Title          string
	Description    string
	Status         string
	Level          string
	Author         string
	Tags           []string
	FalsePositives []string
	Logsource      Logsource
	References     []string
	File           string
	Enabled        bool

	// detection
	selections map[string]*selection
	condition  node
	Condition  string

	// correlation
	Correlation *Correlation

	// Vigil extensions
	Response   *Response
	Compliance []string

	Source string // original YAML
}

type Logsource struct {
	Category string
	Product  string
	Service  string
}

// Correlation follows the Sigma v2 correlation rule specification.
type Correlation struct {
	Type      string   // event_count | value_count
	Rules     []string // referenced rule names or ids
	GroupBy   []string
	Timespan  time.Duration
	Field     string // for value_count
	Op        string // gte | gt | lte | lt | eq
	Threshold int
}

// Response is an automatic active response triggered on match.
type Response struct {
	Action  string            // block_ip | kill_process | quarantine_file
	ArgFrom map[string]string // command arg -> event field, e.g. ip: source.ip
	Timeout string            // e.g. 10m (for block_ip auto-unblock)
}

// IsCorrelation reports whether the rule aggregates other rules' matches.
func (r *Rule) IsCorrelation() bool { return r.Correlation != nil }

// ParseRule parses one Sigma YAML document.
func ParseRule(src string) (*Rule, error) {
	docAny, err := yamlite.Parse(src)
	if err != nil {
		return nil, err
	}
	doc, ok := docAny.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("rule is not a YAML map")
	}
	r := &Rule{
		ID:          str(doc["id"]),
		Name:        str(doc["name"]),
		Title:       str(doc["title"]),
		Description: strings.TrimSpace(str(doc["description"])),
		Status:      str(doc["status"]),
		Level:       strings.ToLower(str(doc["level"])),
		Author:      str(doc["author"]),
		Tags:        strList(doc["tags"]),
		References:  strList(doc["references"]),
		Compliance:  strList(doc["compliance"]),
		Enabled:     true,
		Source:      src,
	}
	r.FalsePositives = strList(doc["falsepositives"])
	if r.Title == "" {
		return nil, fmt.Errorf("rule has no title")
	}
	if r.ID == "" {
		r.ID = slug(r.Title)
	}
	if r.Level == "" {
		r.Level = "medium"
	}
	if ls, ok := doc["logsource"].(map[string]any); ok {
		r.Logsource = Logsource{
			Category: strings.ToLower(str(ls["category"])),
			Product:  strings.ToLower(str(ls["product"])),
			Service:  strings.ToLower(str(ls["service"])),
		}
	}
	if resp, ok := doc["response"].(map[string]any); ok {
		r.Response = &Response{Action: str(resp["action"]), Timeout: str(resp["timeout"]), ArgFrom: map[string]string{}}
		if args, ok := resp["args"].(map[string]any); ok {
			for k, v := range args {
				r.Response.ArgFrom[k] = str(v)
			}
		}
	}

	if c, ok := doc["correlation"].(map[string]any); ok {
		corr, err := parseCorrelation(c)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.Title, err)
		}
		r.Correlation = corr
		return r, nil
	}

	det, ok := doc["detection"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: missing detection block", r.Title)
	}
	r.selections = map[string]*selection{}
	for name, v := range det {
		if name == "condition" || name == "timeframe" {
			continue
		}
		sel, err := compileSelection(v)
		if err != nil {
			return nil, fmt.Errorf("%s: selection %q: %w", r.Title, name, err)
		}
		r.selections[name] = sel
	}
	switch c := det["condition"].(type) {
	case string:
		r.Condition = c
	case []any:
		// multiple conditions are OR'd
		var parts []string
		for _, x := range c {
			parts = append(parts, "("+str(x)+")")
		}
		r.Condition = strings.Join(parts, " or ")
	default:
		return nil, fmt.Errorf("%s: missing condition", r.Title)
	}
	names := make([]string, 0, len(r.selections))
	for n := range r.selections {
		names = append(names, n)
	}
	sort.Strings(names)
	n, err := parseCondition(r.Condition, names)
	if err != nil {
		return nil, fmt.Errorf("%s: condition: %w", r.Title, err)
	}
	r.condition = n
	return r, nil
}

func parseCorrelation(c map[string]any) (*Correlation, error) {
	corr := &Correlation{
		Type:    str(c["type"]),
		Rules:   strList(c["rules"]),
		GroupBy: strList(c["group-by"]),
	}
	if corr.Type != "event_count" && corr.Type != "value_count" {
		return nil, fmt.Errorf("unsupported correlation type %q", corr.Type)
	}
	if len(corr.Rules) == 0 {
		return nil, fmt.Errorf("correlation needs rules")
	}
	ts := str(c["timespan"])
	if ts == "" {
		ts = str(c["timeframe"])
	}
	d, err := parseDuration(ts)
	if err != nil {
		return nil, err
	}
	corr.Timespan = d
	cond, ok := c["condition"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("correlation needs condition map")
	}
	for _, op := range []string{"gte", "gt", "lte", "lt", "eq"} {
		if v, ok := cond[op]; ok {
			n, err := strconv.Atoi(str(v))
			if err != nil {
				return nil, fmt.Errorf("bad threshold %v", v)
			}
			corr.Op, corr.Threshold = op, n
		}
	}
	if corr.Op == "" {
		return nil, fmt.Errorf("correlation condition needs gte/gt/lte/lt/eq")
	}
	corr.Field = str(cond["field"])
	if corr.Type == "value_count" && corr.Field == "" {
		return nil, fmt.Errorf("value_count needs condition.field")
	}
	return corr, nil
}

// parseDuration accepts Sigma style 30s, 5m, 1h, 1d.
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("missing timespan")
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, err
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// Satisfied evaluates a correlation threshold.
func (c *Correlation) Satisfied(n int) bool {
	switch c.Op {
	case "gte":
		return n >= c.Threshold
	case "gt":
		return n > c.Threshold
	case "lte":
		return n <= c.Threshold
	case "lt":
		return n < c.Threshold
	case "eq":
		return n == c.Threshold
	}
	return false
}

// MITRE extracts ATT&CK technique/tactic IDs from tags like attack.t1110.001.
func (r *Rule) MITRE() []string {
	var out []string
	for _, t := range r.Tags {
		t = strings.ToLower(t)
		if !strings.HasPrefix(t, "attack.") {
			continue
		}
		v := strings.TrimPrefix(t, "attack.")
		if len(v) > 1 && (v[0] == 't') && v[1] >= '0' && v[1] <= '9' {
			out = append(out, strings.ToUpper(v))
		} else if strings.HasPrefix(v, "ta") && len(v) > 2 && v[2] >= '0' && v[2] <= '9' {
			out = append(out, strings.ToUpper(v))
		}
	}
	return out
}

// Tactics returns the ATT&CK tactic names from tags (attack.credential-access).
func (r *Rule) Tactics() []string {
	var out []string
	for _, t := range r.Tags {
		t = strings.ToLower(t)
		if !strings.HasPrefix(t, "attack.") {
			continue
		}
		v := strings.TrimPrefix(t, "attack.")
		if len(v) > 0 && !(v[0] == 't' && len(v) > 1 && v[1] >= '0' && v[1] <= '9') && !strings.HasPrefix(v, "ta0") && !strings.HasPrefix(v, "g0") && !strings.HasPrefix(v, "s0") {
			out = append(out, v)
		}
	}
	return out
}

// LoadDir loads every *.yml / *.yaml file (multi-document allowed) under dir.
func LoadDir(dir string) ([]*Rule, []error) {
	var rules []*Rule
	var errs []error
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		for _, doc := range splitDocs(string(b)) {
			r, err := ParseRule(doc)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", path, err))
				continue
			}
			r.File = path
			rules = append(rules, r)
		}
		return nil
	})
	return rules, errs
}

func splitDocs(s string) []string {
	var docs []string
	var cur []string
	for _, l := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(l) == "---" {
			if strings.TrimSpace(strings.Join(cur, "")) != "" {
				docs = append(docs, strings.Join(cur, "\n"))
			}
			cur = nil
			continue
		}
		cur = append(cur, l)
	}
	if strings.TrimSpace(strings.Join(cur, "")) != "" {
		docs = append(docs, strings.Join(cur, "\n"))
	}
	return docs
}

func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func strList(v any) []string {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		return []string{x}
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			out = append(out, str(e))
		}
		return out
	}
	return nil
}

func slug(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if b.Len() > 0 && !strings.HasSuffix(b.String(), "_") {
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}
