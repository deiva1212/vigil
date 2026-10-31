package server

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigil-siem/vigil/internal/common"
	"github.com/vigil-siem/vigil/internal/sigma"
)

// Engine runs decoding, Sigma detection and correlation over incoming events.
type Engine struct {
	mu        sync.RWMutex
	rules     []*sigma.Rule
	corr      []*sigma.Rule
	byRef     map[string][]*sigma.Rule // base rule name or id -> correlations
	ruleByID  map[string]*sigma.Rule
	hits      map[string]*int64
	loadErrs  []string
	disabled  map[string]bool
	windows   map[string]*corrWindow
	windowsMu sync.Mutex

	cfg       *Config
	store     *Store
	notifier  *Notifier
	responder *Responder
	hub       *Hub
	minLevel  int

	processed atomic.Int64
}

type corrEntry struct {
	at      time.Time
	value   string
	eventID string
	agentID string
	host    string
}

type corrWindow struct {
	entries   []corrEntry
	lastFired time.Time
}

func NewEngine(cfg *Config, store *Store, n *Notifier, r *Responder, hub *Hub) *Engine {
	e := &Engine{cfg: cfg, store: store, notifier: n, responder: r, hub: hub,
		windows: map[string]*corrWindow{}, disabled: map[string]bool{}}
	e.minLevel = levelRank[cfg.MinAlertLevel]
	if b, err := os.ReadFile(filepath.Join(cfg.DataDir, "rules_state.json")); err == nil {
		_ = json.Unmarshal(b, &e.disabled)
	}
	return e
}

// LoadRules (re)loads bundled and custom rules.
func (e *Engine) LoadRules() error {
	var all []*sigma.Rule
	var errs []string
	for _, dir := range []string{e.cfg.RulesDir, e.customRulesDir()} {
		if dir == "" {
			continue
		}
		rs, es := sigma.LoadDir(dir)
		all = append(all, rs...)
		for _, x := range es {
			errs = append(errs, x.Error())
		}
	}
	byRef := map[string][]*sigma.Rule{}
	byID := map[string]*sigma.Rule{}
	var det, corr []*sigma.Rule
	e.mu.RLock()
	oldHits := e.hits
	e.mu.RUnlock()
	hits := map[string]*int64{}
	for _, r := range all {
		if _, dup := byID[r.ID]; dup {
			errs = append(errs, fmt.Sprintf("%s: duplicate rule id %s (skipped)", r.File, r.ID))
			continue
		}
		byID[r.ID] = r
		r.Enabled = !e.disabled[r.ID]
		if h, ok := oldHits[r.ID]; ok {
			hits[r.ID] = h
		} else {
			hits[r.ID] = new(int64)
		}
		if r.IsCorrelation() {
			corr = append(corr, r)
			for _, ref := range r.Correlation.Rules {
				byRef[ref] = append(byRef[ref], r)
			}
		} else {
			det = append(det, r)
		}
	}
	for _, c := range corr {
		for _, ref := range c.Correlation.Rules {
			found := false
			for _, r := range det {
				if r.Name == ref || r.ID == ref {
					found = true
				}
			}
			if !found {
				errs = append(errs, fmt.Sprintf("%s: correlation references unknown rule %q", c.Title, ref))
			}
		}
	}
	e.mu.Lock()
	e.rules, e.corr, e.byRef, e.ruleByID, e.hits, e.loadErrs = det, corr, byRef, byID, hits, errs
	e.mu.Unlock()
	log.Printf("rules: %d detection, %d correlation, %d errors", len(det), len(corr), len(errs))
	for _, x := range errs {
		log.Printf("rules: %s", x)
	}
	return nil
}

func (e *Engine) customRulesDir() string { return filepath.Join(e.cfg.DataDir, "rules") }

// Ingest decodes, stores and analyses a batch of events.
func (e *Engine) Ingest(events []*common.Event) {
	for _, ev := range events {
		Decode(ev)
	}
	e.store.AddEvents(events)
	for _, ev := range events {
		e.detect(ev)
	}
	e.processed.Add(int64(len(events)))
	e.hub.Publish("events", map[string]int{"count": len(events)})
}

func (e *Engine) detect(ev *common.Event) {
	e.mu.RLock()
	rules := e.rules
	byRef := e.byRef
	e.mu.RUnlock()
	for _, r := range rules {
		if !r.Matches(ev) {
			continue
		}
		e.mu.RLock()
		if h := e.hits[r.ID]; h != nil {
			atomic.AddInt64(h, 1)
		}
		e.mu.RUnlock()
		for _, ref := range []string{r.Name, r.ID} {
			if ref == "" {
				continue
			}
			for _, c := range byRef[ref] {
				if c.Enabled {
					e.correlate(c, ev)
				}
			}
		}
		if levelRank[r.Level] >= e.minLevel {
			e.alertFromRule(r, ev)
		}
	}
}

// dedupKey folds repeats of a detection into one alert, keyed on the main
// entity: the remote address when there is one (scans, brute force),
// otherwise the user, file or process involved.
func dedupKey(r *sigma.Rule, ev *common.Event) string {
	f := ev.Fields
	if ip := f["source.ip"]; ip != "" {
		return strings.Join([]string{r.ID, ev.AgentID, "ip", ip}, "|")
	}
	return strings.Join([]string{r.ID, ev.AgentID, f["user.name"], f["user.target"], f["file.path"], f["process.pid"]}, "|")
}

func (e *Engine) alertFromRule(r *sigma.Rule, ev *common.Event) {
	a := &common.Alert{
		ID: common.NewID(), RuleID: r.ID, RuleTitle: r.Title, Level: r.Level,
		Score: common.LevelScore(r.Level), AgentID: ev.AgentID, Hostname: ev.Hostname,
		Timestamp: time.Now(), LastSeen: time.Now(), Description: DescribeEvent(ev),
		Tags: r.Tags, MITRE: nonNil(r.MITRE()), EventIDs: []string{ev.ID}, Status: "open",
		Kind: "sigma", Count: 1, Fields: copyFields(ev.Fields),
	}
	a.Fields["event.category"] = ev.Category
	a.Fields["log.source"] = ev.Source
	a.Compliance = MapCompliance(r.Tags, a.Kind, r.Compliance)
	stored, isNew := e.store.AddAlert(a, dedupKey(r, ev), e.cfg.DedupWindow)
	if !isNew {
		return
	}
	e.afterAlert(stored, r, []map[string]string{ev.Fields}, []string{ev.AgentID})
}

func (e *Engine) correlate(c *sigma.Rule, ev *common.Event) {
	cr := c.Correlation
	var keyParts []string
	for _, g := range cr.GroupBy {
		v := ev.Fields[g]
		if g == "host.name" && v == "" {
			v = ev.Hostname
		}
		if v == "" {
			return // can't group: skip
		}
		keyParts = append(keyParts, v)
	}
	key := c.ID + "|" + strings.Join(keyParts, "|")
	now := time.Now()

	e.windowsMu.Lock()
	w := e.windows[key]
	if w == nil {
		w = &corrWindow{}
		e.windows[key] = w
	}
	val := ""
	if cr.Field != "" {
		val = ev.Fields[cr.Field]
	}
	w.entries = append(w.entries, corrEntry{at: now, value: val, eventID: ev.ID, agentID: ev.AgentID, host: ev.Hostname})
	cut := now.Add(-cr.Timespan)
	i := 0
	for i < len(w.entries) && w.entries[i].at.Before(cut) {
		i++
	}
	w.entries = w.entries[i:]
	n := len(w.entries)
	distinct := map[string]bool{}
	if cr.Type == "value_count" {
		for _, en := range w.entries {
			if en.value != "" {
				distinct[en.value] = true
			}
		}
		n = len(distinct)
	}
	fire := cr.Satisfied(n) && now.Sub(w.lastFired) > cr.Timespan
	var entries []corrEntry
	if fire {
		w.lastFired = now
		entries = append(entries, w.entries...)
		w.entries = nil
	}
	e.windowsMu.Unlock()
	if !fire {
		return
	}

	fields := map[string]string{"correlation.type": cr.Type, "correlation.count": strconv.Itoa(n), "correlation.timespan": cr.Timespan.String()}
	for i, g := range cr.GroupBy {
		fields[g] = keyParts[i]
	}
	var vals []string
	for v := range distinct {
		vals = append(vals, v)
	}
	sort.Strings(vals)
	if len(vals) > 0 {
		fields["correlation.values"] = strings.Join(vals, ", ")
	}
	agents := map[string]string{}
	var evIDs []string
	for _, en := range entries {
		agents[en.agentID] = en.host
		if len(evIDs) < 50 {
			evIDs = append(evIDs, en.eventID)
		}
	}
	var hosts, agentIDs []string
	for id, h := range agents {
		agentIDs = append(agentIDs, id)
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	desc := fmt.Sprintf("%d matching events within %s grouped by %s=%s", n, cr.Timespan, strings.Join(cr.GroupBy, ","), strings.Join(keyParts, ","))
	if cr.Type == "value_count" {
		desc = fmt.Sprintf("%d distinct %s values within %s for %s=%s", n, cr.Field, cr.Timespan, strings.Join(cr.GroupBy, ","), strings.Join(keyParts, ","))
	}
	a := &common.Alert{
		ID: common.NewID(), RuleID: c.ID, RuleTitle: c.Title, Level: c.Level,
		Score: common.LevelScore(c.Level), AgentID: ev.AgentID, Hostname: strings.Join(hosts, ", "),
		Timestamp: now, LastSeen: now, Description: desc, Tags: c.Tags, MITRE: nonNil(c.MITRE()),
		EventIDs: evIDs, Status: "open", Kind: "correlation", Count: 1, Fields: fields,
	}
	a.Compliance = MapCompliance(c.Tags, a.Kind, c.Compliance)
	stored, isNew := e.store.AddAlert(a, "", 0)
	if isNew {
		e.afterAlert(stored, c, []map[string]string{fields}, agentIDs)
	}
}

func (e *Engine) afterAlert(a *common.Alert, r *sigma.Rule, fieldSets []map[string]string, agentIDs []string) {
	e.hub.Publish("alert", a)
	e.notifier.Notify(a)
	if r != nil && r.Response != nil && e.cfg.AutoResponse {
		ids := e.responder.FromRule(r, a, fieldSets[0], agentIDs)
		if len(ids) > 0 {
			e.store.UpdateAlert(a.ID, func(x *common.Alert) { x.Response = strings.Join(ids, ",") })
		}
	}
}

// SystemAlert raises a non-Sigma alert (vulnerability, SCA, agent health).
func (e *Engine) SystemAlert(kind, ruleID, title, level string, agent *common.AgentInfo, desc string, tags []string, fields map[string]string, dedup string, compliance []string) {
	a := &common.Alert{
		ID: common.NewID(), RuleID: ruleID, RuleTitle: title, Level: level,
		Score: common.LevelScore(level), Timestamp: time.Now(), LastSeen: time.Now(),
		Description: desc, Tags: tags, Status: "open", Kind: kind, Count: 1, Fields: fields, MITRE: []string{},
	}
	if agent != nil {
		a.AgentID, a.Hostname = agent.ID, agent.Name
	}
	if a.Fields == nil {
		a.Fields = map[string]string{}
	}
	for _, t := range tags {
		if isTechniqueTag(strings.ToLower(t)) {
			a.MITRE = append(a.MITRE, strings.ToUpper(strings.TrimPrefix(strings.ToLower(t), "attack.")))
		}
	}
	a.Compliance = MapCompliance(tags, kind, compliance)
	if levelRank[level] < e.minLevel {
		return
	}
	stored, isNew := e.store.AddAlert(a, dedup, 24*time.Hour)
	if isNew {
		e.afterAlert(stored, nil, nil, nil)
	}
}

func copyFields(f map[string]string) map[string]string {
	out := make(map[string]string, len(f)+2)
	for k, v := range f {
		out[k] = v
	}
	return out
}

// ------------------------------------------------------------ rule admin

type RuleInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Level       string   `json:"level"`
	Status      string   `json:"status"`
	Type        string   `json:"type"`
	Tags        []string `json:"tags"`
	MITRE       []string `json:"mitre"`
	Logsource   string   `json:"logsource"`
	File        string   `json:"file"`
	Enabled     bool     `json:"enabled"`
	Hits        int64    `json:"hits"`
	Response    string   `json:"response,omitempty"`
	Custom      bool     `json:"custom"`
}

func (e *Engine) RuleInfos() ([]RuleInfo, []string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var out []RuleInfo
	add := func(r *sigma.Rule, typ string) {
		ls := strings.Trim(strings.Join([]string{r.Logsource.Product, r.Logsource.Category, r.Logsource.Service}, "/"), "/")
		ls = strings.ReplaceAll(ls, "//", "/")
		ri := RuleInfo{ID: r.ID, Name: r.Name, Title: r.Title, Description: r.Description, Level: r.Level,
			Status: r.Status, Type: typ, Tags: r.Tags, MITRE: r.MITRE(), Logsource: ls,
			File: filepath.Base(r.File), Enabled: r.Enabled, Custom: strings.HasPrefix(r.File, e.customRulesDir())}
		if h := e.hits[r.ID]; h != nil {
			ri.Hits = atomic.LoadInt64(h)
		}
		if r.Response != nil {
			ri.Response = r.Response.Action
		}
		if ri.Tags == nil {
			ri.Tags = []string{}
		}
		if ri.MITRE == nil {
			ri.MITRE = []string{}
		}
		if r.IsCorrelation() {
			ri.Logsource = r.Correlation.Type + " over " + strings.Join(r.Correlation.Rules, ", ")
		}
		out = append(out, ri)
	}
	for _, r := range e.rules {
		add(r, "detection")
	}
	for _, r := range e.corr {
		add(r, "correlation")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, e.loadErrs
}

func (e *Engine) RuleSource(id string) (string, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	r := e.ruleByID[id]
	if r == nil {
		return "", false
	}
	return r.Source, true
}

func (e *Engine) SetEnabled(id string, enabled bool) bool {
	e.mu.Lock()
	r := e.ruleByID[id]
	if r == nil {
		e.mu.Unlock()
		return false
	}
	r.Enabled = enabled
	if enabled {
		delete(e.disabled, id)
	} else {
		e.disabled[id] = true
	}
	b, _ := json.Marshal(e.disabled)
	e.mu.Unlock()
	_ = os.WriteFile(filepath.Join(e.cfg.DataDir, "rules_state.json"), b, 0o640)
	return true
}

// SaveCustomRule validates and stores a rule, then reloads.
func (e *Engine) SaveCustomRule(src string) (*sigma.Rule, error) {
	r, err := sigma.ParseRule(src)
	if err != nil {
		return nil, err
	}
	e.mu.RLock()
	existing := e.ruleByID[r.ID]
	e.mu.RUnlock()
	if existing != nil && !strings.HasPrefix(existing.File, e.customRulesDir()) {
		return nil, fmt.Errorf("rule id %s belongs to a bundled rule; choose a new id", r.ID)
	}
	if err := os.MkdirAll(e.customRulesDir(), 0o750); err != nil {
		return nil, err
	}
	name := strings.Map(func(c rune) rune {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			return c
		}
		return '_'
	}, r.ID)
	if err := os.WriteFile(filepath.Join(e.customRulesDir(), name+".yml"), []byte(src), 0o640); err != nil {
		return nil, err
	}
	return r, e.LoadRules()
}

func (e *Engine) DeleteCustomRule(id string) error {
	e.mu.RLock()
	r := e.ruleByID[id]
	e.mu.RUnlock()
	if r == nil {
		return fmt.Errorf("no such rule")
	}
	if !strings.HasPrefix(r.File, e.customRulesDir()) {
		return fmt.Errorf("bundled rules can be disabled but not deleted")
	}
	if err := os.Remove(r.File); err != nil {
		return err
	}
	return e.LoadRules()
}

// TestRule evaluates a rule against recent events without raising alerts.
func (e *Engine) TestRule(src string, limit int) ([]*common.Event, int, error) {
	r, err := sigma.ParseRule(src)
	if err != nil {
		return nil, 0, err
	}
	if r.IsCorrelation() {
		return nil, 0, fmt.Errorf("test correlation rules by testing the rules they reference")
	}
	scanned := 0
	matches := e.store.RecentEvents(limit, func(ev *common.Event) bool {
		scanned++
		return r.Matches(ev)
	})
	if len(matches) > 200 {
		matches = matches[:200]
	}
	return matches, scanned, nil
}

func (e *Engine) Processed() int64 { return e.processed.Load() }

// GC drops idle correlation windows.
func (e *Engine) GC() {
	e.windowsMu.Lock()
	defer e.windowsMu.Unlock()
	cut := time.Now().Add(-2 * time.Hour)
	for k, w := range e.windows {
		if len(w.entries) == 0 || w.entries[len(w.entries)-1].at.Before(cut) {
			if w.lastFired.Before(cut) {
				delete(e.windows, k)
			}
		}
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
