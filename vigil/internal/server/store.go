package server

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vigil-siem/vigil/internal/common"
)

// VulnFinding is a CVE matched against an agent's installed package.
type VulnFinding struct {
	CVE        string    `json:"cve"`
	AgentID    string    `json:"agent_id"`
	Hostname   string    `json:"hostname"`
	Package    string    `json:"package"`
	Version    string    `json:"version"`
	Fixed      string    `json:"fixed"`
	Severity   string    `json:"severity"`
	CVSS       float64   `json:"cvss"`
	Summary    string    `json:"summary"`
	References []string  `json:"references"`
	DetectedAt time.Time `json:"detected_at"`
}

// Store keeps hot data in memory and persists it to the data directory.
//
// Events: in-memory ring buffer + daily JSONL archive files (events/YYYY-MM-DD.jsonl).
// Everything else: JSON snapshots written every few seconds when dirty.
//
// This is deliberately simple. For production scale swap the event path for
// OpenSearch / ClickHouse (see docs/ARCHITECTURE.md, "Scaling storage").
type Store struct {
	mu  sync.RWMutex
	dir string

	agents    map[string]*common.AgentInfo
	alerts    []*common.Alert
	alertByID map[string]*common.Alert
	commands  []*common.Command
	inventory map[string]*common.Inventory
	sca       map[string]*common.SCAReport
	vulns     map[string][]VulnFinding

	events    []*common.Event // ring
	evHead    int
	evCount   int
	maxEvents int
	maxAlerts int

	evFile *os.File
	evDay  string
	evBuf  *bufio.Writer

	totalEvents int64
	dirty       bool
	minuteHist  map[int64]int64 // unix minute -> events
	alertHist   map[int64]int64 // unix minute -> alerts
}

type snapshot struct {
	Agents    map[string]*common.AgentInfo `json:"agents"`
	Alerts    []*common.Alert              `json:"alerts"`
	Commands  []*common.Command            `json:"commands"`
	Inventory map[string]*common.Inventory `json:"inventory"`
	SCA       map[string]*common.SCAReport `json:"sca"`
	Vulns     map[string][]VulnFinding     `json:"vulns"`
	Total     int64                        `json:"total_events"`
}

func NewStore(dir string, maxEvents, maxAlerts int) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "events"), 0o750); err != nil {
		return nil, err
	}
	s := &Store{
		dir:        dir,
		agents:     map[string]*common.AgentInfo{},
		alertByID:  map[string]*common.Alert{},
		inventory:  map[string]*common.Inventory{},
		sca:        map[string]*common.SCAReport{},
		vulns:      map[string][]VulnFinding{},
		events:     make([]*common.Event, maxEvents),
		maxEvents:  maxEvents,
		maxAlerts:  maxAlerts,
		minuteHist: map[int64]int64{},
		alertHist:  map[int64]int64{},
	}
	if b, err := os.ReadFile(filepath.Join(dir, "state.json")); err == nil {
		var snap snapshot
		if err := json.Unmarshal(b, &snap); err != nil {
			log.Printf("store: state.json unreadable, starting fresh: %v", err)
		} else {
			if snap.Agents != nil {
				s.agents = snap.Agents
			}
			s.alerts = snap.Alerts
			for _, a := range s.alerts {
				s.alertByID[a.ID] = a
				s.alertHist[a.Timestamp.Unix()/60]++
			}
			s.commands = snap.Commands
			if snap.Inventory != nil {
				s.inventory = snap.Inventory
			}
			if snap.SCA != nil {
				s.sca = snap.SCA
			}
			if snap.Vulns != nil {
				s.vulns = snap.Vulns
			}
			s.totalEvents = snap.Total
		}
	}
	s.loadRecentEvents()
	return s, nil
}

// loadRecentEvents warms the ring buffer from the last two archive files.
func (s *Store) loadRecentEvents() {
	files, _ := filepath.Glob(filepath.Join(s.dir, "events", "*.jsonl"))
	sort.Strings(files)
	if len(files) > 2 {
		files = files[len(files)-2:]
	}
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
		for sc.Scan() {
			var e common.Event
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				s.pushEvent(&e)
				s.minuteHist[e.Timestamp.Unix()/60]++
			}
		}
		fh.Close()
	}
}

func (s *Store) pushEvent(e *common.Event) {
	s.events[s.evHead] = e
	s.evHead = (s.evHead + 1) % s.maxEvents
	if s.evCount < s.maxEvents {
		s.evCount++
	}
}

// AddEvents appends events to memory and the daily archive.
func (s *Store) AddEvents(evs []*common.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range evs {
		s.pushEvent(e)
		s.totalEvents++
		s.minuteHist[e.Timestamp.Unix()/60]++
		if a := s.agents[e.AgentID]; a != nil {
			a.EventCount++
		}
		s.archive(e)
	}
	s.dirty = true
}

func (s *Store) archive(e *common.Event) {
	day := time.Now().UTC().Format("2006-01-02")
	if day != s.evDay || s.evFile == nil {
		if s.evBuf != nil {
			s.evBuf.Flush()
			s.evFile.Close()
		}
		f, err := os.OpenFile(filepath.Join(s.dir, "events", day+".jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			log.Printf("store: archive open: %v", err)
			return
		}
		s.evFile, s.evDay, s.evBuf = f, day, bufio.NewWriterSize(f, 256*1024)
	}
	b, _ := json.Marshal(e)
	s.evBuf.Write(b)
	s.evBuf.WriteByte('\n')
}

// RecentEvents returns up to n events, newest first, passing filter.
func (s *Store) RecentEvents(n int, filter func(*common.Event) bool) []*common.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*common.Event, 0, min(n, 1000))
	for i := 0; i < s.evCount && len(out) < n; i++ {
		idx := (s.evHead - 1 - i + s.maxEvents) % s.maxEvents
		e := s.events[idx]
		if e != nil && (filter == nil || filter(e)) {
			out = append(out, e)
		}
	}
	return out
}

// OldestInMemory is the timestamp of the oldest buffered event.
func (s *Store) OldestInMemory() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.evCount == 0 {
		return time.Now()
	}
	idx := (s.evHead - s.evCount + s.maxEvents) % s.maxEvents
	if e := s.events[idx]; e != nil {
		return e.Timestamp
	}
	return time.Now()
}

// ArchiveScan streams archived events between from and to (inclusive days).
func (s *Store) ArchiveScan(from, to time.Time, fn func(*common.Event) bool) {
	s.mu.Lock()
	if s.evBuf != nil {
		s.evBuf.Flush()
	}
	s.mu.Unlock()
	for d := from.UTC().Truncate(24 * time.Hour); !d.After(to); d = d.Add(24 * time.Hour) {
		f, err := os.Open(filepath.Join(s.dir, "events", d.Format("2006-01-02")+".jsonl"))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
		for sc.Scan() {
			var e common.Event
			if json.Unmarshal(sc.Bytes(), &e) != nil {
				continue
			}
			if e.Timestamp.Before(from) || e.Timestamp.After(to) {
				continue
			}
			if !fn(&e) {
				f.Close()
				return
			}
		}
		f.Close()
	}
}

// ------------------------------------------------------------------ agents

func (s *Store) PutAgent(a *common.AgentInfo) {
	s.mu.Lock()
	s.agents[a.ID] = a
	s.dirty = true
	s.mu.Unlock()
}

func (s *Store) Agent(id string) *common.AgentInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.agents[id]
}

func (s *Store) Agents() []*common.AgentInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*common.AgentInfo, 0, len(s.agents))
	for _, a := range s.agents {
		cp := *a
		cp.TokenHash = ""
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Store) UpdateAgent(id string, fn func(a *common.AgentInfo)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.agents[id]
	if a == nil {
		return false
	}
	fn(a)
	s.dirty = true
	return true
}

func (s *Store) DeleteAgent(id string) {
	s.mu.Lock()
	delete(s.agents, id)
	delete(s.inventory, id)
	delete(s.sca, id)
	delete(s.vulns, id)
	s.dirty = true
	s.mu.Unlock()
}

// ------------------------------------------------------------------ alerts

// AddAlert stores an alert, folding duplicates (same rule, agent and key)
// seen within dedupWindow into the existing alert. Returns the stored alert
// and whether it is new.
func (s *Store) AddAlert(a *common.Alert, dedupKey string, dedupWindow time.Duration) (*common.Alert, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alertHist[a.Timestamp.Unix()/60]++
	if dedupKey != "" {
		for i := len(s.alerts) - 1; i >= 0 && i >= len(s.alerts)-500; i-- {
			ex := s.alerts[i]
			if ex.Fields["_dedup"] == dedupKey && ex.Status == "open" && a.Timestamp.Sub(ex.LastSeen) < dedupWindow {
				ex.Count++
				ex.LastSeen = a.Timestamp
				if len(ex.EventIDs) < 50 {
					ex.EventIDs = append(ex.EventIDs, a.EventIDs...)
				}
				s.dirty = true
				return ex, false
			}
		}
		a.Fields["_dedup"] = dedupKey
	}
	s.alerts = append(s.alerts, a)
	s.alertByID[a.ID] = a
	if len(s.alerts) > s.maxAlerts {
		drop := s.alerts[:len(s.alerts)-s.maxAlerts]
		for _, d := range drop {
			delete(s.alertByID, d.ID)
		}
		s.alerts = append([]*common.Alert(nil), s.alerts[len(s.alerts)-s.maxAlerts:]...)
	}
	s.dirty = true
	return a, true
}

func (s *Store) Alerts(filter func(*common.Alert) bool, limit int) []*common.Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*common.Alert
	for i := len(s.alerts) - 1; i >= 0 && len(out) < limit; i-- {
		if filter == nil || filter(s.alerts[i]) {
			out = append(out, s.alerts[i])
		}
	}
	return out
}

func (s *Store) Alert(id string) *common.Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.alertByID[id]
}

func (s *Store) UpdateAlert(id string, fn func(*common.Alert)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.alertByID[id]
	if a == nil {
		return false
	}
	fn(a)
	s.dirty = true
	return true
}

// ---------------------------------------------------------------- commands

func (s *Store) AddCommand(c *common.Command) {
	s.mu.Lock()
	s.commands = append(s.commands, c)
	if len(s.commands) > 5000 {
		s.commands = s.commands[len(s.commands)-5000:]
	}
	s.dirty = true
	s.mu.Unlock()
}

// TakePending marks pending commands for an agent as delivered and returns them.
func (s *Store) TakePending(agentID string) []common.Command {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []common.Command
	now := time.Now()
	for _, c := range s.commands {
		if c.AgentID == agentID && c.Status == "pending" {
			c.Status = "delivered"
			c.UpdatedAt = now
			out = append(out, *c)
		}
	}
	if len(out) > 0 {
		s.dirty = true
	}
	return out
}

func (s *Store) CompleteCommand(agentID string, r common.CommandResult) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.commands {
		if c.ID == r.CommandID && c.AgentID == agentID {
			c.Status = r.Status
			c.Result = r.Output
			c.UpdatedAt = time.Now()
			s.dirty = true
			return true
		}
	}
	return false
}

func (s *Store) Commands(limit int) []*common.Command {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*common.Command
	for i := len(s.commands) - 1; i >= 0 && len(out) < limit; i-- {
		cp := *s.commands[i]
		out = append(out, &cp)
	}
	return out
}

// --------------------------------------------------------- inventory & SCA

func (s *Store) PutInventory(inv *common.Inventory) {
	s.mu.Lock()
	s.inventory[inv.AgentID] = inv
	if a := s.agents[inv.AgentID]; a != nil {
		a.PackageCount = len(inv.Packages)
	}
	s.dirty = true
	s.mu.Unlock()
}

func (s *Store) Inventory(agentID string) *common.Inventory {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inventory[agentID]
}

// PutSCA stores a report and returns the previous one (for diffing).
func (s *Store) PutSCA(r *common.SCAReport) *common.SCAReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.sca[r.AgentID]
	s.sca[r.AgentID] = r
	if a := s.agents[r.AgentID]; a != nil {
		a.SCAScore = scaScore(r)
	}
	s.dirty = true
	return prev
}

func scaScore(r *common.SCAReport) int {
	pass, total := 0, 0
	for _, c := range r.Results {
		if c.Result == "not_applicable" {
			continue
		}
		total++
		if c.Result == "passed" {
			pass++
		}
	}
	if total == 0 {
		return 0
	}
	return pass * 100 / total
}

func (s *Store) SCA(agentID string) *common.SCAReport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sca[agentID]
}

func (s *Store) AllSCA() map[string]*common.SCAReport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]*common.SCAReport, len(s.sca))
	for k, v := range s.sca {
		out[k] = v
	}
	return out
}

// PutVulns replaces an agent's findings and returns the ones that are new.
func (s *Store) PutVulns(agentID string, findings []VulnFinding) []VulnFinding {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := map[string]bool{}
	for _, f := range s.vulns[agentID] {
		old[f.CVE+"|"+f.Package] = true
	}
	var fresh []VulnFinding
	for _, f := range findings {
		if !old[f.CVE+"|"+f.Package] {
			fresh = append(fresh, f)
		}
	}
	s.vulns[agentID] = findings
	if a := s.agents[agentID]; a != nil {
		a.VulnCount = len(findings)
	}
	s.dirty = true
	return fresh
}

func (s *Store) Vulns(agentID string) []VulnFinding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if agentID != "" {
		return append([]VulnFinding(nil), s.vulns[agentID]...)
	}
	var out []VulnFinding
	for _, v := range s.vulns {
		out = append(out, v...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CVSS > out[j].CVSS })
	return out
}

// ------------------------------------------------------------------- stats

type Stats struct {
	TotalEvents    int64          `json:"total_events"`
	EventsLastHour int64          `json:"events_last_hour"`
	EPS            float64        `json:"eps"`
	Alerts         int            `json:"alerts"`
	OpenAlerts     int            `json:"open_alerts"`
	ByLevel        map[string]int `json:"by_level"`
	TopRules       []KV           `json:"top_rules"`
	TopAgents      []KV           `json:"top_agents"`
	TopSources     []KV           `json:"top_sources"`
	Tactics        []KV           `json:"tactics"`
	Agents         map[string]int `json:"agents"`
	EventTimeline  []int64        `json:"event_timeline"` // 24 hourly buckets, oldest first
	AlertTimeline  []int64        `json:"alert_timeline"`
	Vulns          map[string]int `json:"vulns"`
	AvgSCA         int            `json:"avg_sca"`
}

type KV struct {
	Key   string `json:"key"`
	Label string `json:"label,omitempty"`
	Value int    `json:"value"`
}

func topN(m map[string]int, n int) []KV {
	out := make([]KV, 0, len(m))
	for k, v := range m {
		out = append(out, KV{Key: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Value == out[j].Value {
			return out[i].Key < out[j].Key
		}
		return out[i].Value > out[j].Value
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func (s *Store) Stats(since time.Time) Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := Stats{
		TotalEvents: s.totalEvents,
		ByLevel:     map[string]int{},
		Agents:      map[string]int{},
		Vulns:       map[string]int{},
	}
	now := time.Now()
	nowMin := now.Unix() / 60
	for m, c := range s.minuteHist {
		if nowMin-m < 60 {
			st.EventsLastHour += c
		}
	}
	var last5 int64
	for m := nowMin - 4; m <= nowMin; m++ {
		last5 += s.minuteHist[m]
	}
	st.EPS = float64(last5) / 300
	st.EventTimeline = hourly(s.minuteHist, now)
	st.AlertTimeline = hourly(s.alertHist, now)

	rules, agents, tactics := map[string]int{}, map[string]int{}, map[string]int{}
	ruleTitle := map[string]string{}
	for _, a := range s.alerts {
		if a.Timestamp.Before(since) {
			continue
		}
		st.Alerts++
		if a.Status == "open" {
			st.OpenAlerts++
		}
		st.ByLevel[a.Level]++
		rules[a.RuleID] += max(a.Count, 1)
		ruleTitle[a.RuleID] = a.RuleTitle
		agents[a.Hostname]++
		for _, t := range a.Tags {
			if strings.HasPrefix(t, "attack.") && !isTechniqueTag(t) {
				tactics[strings.TrimPrefix(t, "attack.")]++
			}
		}
	}
	st.TopRules = topN(rules, 8)
	for i := range st.TopRules {
		st.TopRules[i].Label = ruleTitle[st.TopRules[i].Key]
	}
	st.TopAgents = topN(agents, 8)
	st.Tactics = topN(tactics, 14)

	srcs := map[string]int{}
	for i := 0; i < s.evCount && i < 20000; i++ {
		idx := (s.evHead - 1 - i + s.maxEvents) % s.maxEvents
		if e := s.events[idx]; e != nil {
			k := e.Category
			if svc := e.Fields["log.service"]; svc != "" {
				k += ":" + svc
			}
			srcs[k]++
		}
	}
	st.TopSources = topN(srcs, 8)

	for _, a := range s.agents {
		st.Agents[a.Status]++
		st.Agents["total"]++
	}
	scaSum, scaN := 0, 0
	for _, r := range s.sca {
		scaSum += scaScore(r)
		scaN++
	}
	if scaN > 0 {
		st.AvgSCA = scaSum / scaN
	}
	for _, vs := range s.vulns {
		for _, v := range vs {
			st.Vulns[v.Severity]++
			st.Vulns["total"]++
		}
	}
	return st
}

func isTechniqueTag(t string) bool {
	v := strings.TrimPrefix(t, "attack.")
	return len(v) > 1 && v[0] == 't' && v[1] >= '0' && v[1] <= '9'
}

func hourly(h map[int64]int64, now time.Time) []int64 {
	out := make([]int64, 24)
	nowMin := now.Unix() / 60
	for m, c := range h {
		age := nowMin - m
		if age < 0 || age >= 24*60 {
			continue
		}
		out[23-int(age/60)] += c
	}
	return out
}

// ------------------------------------------------------------- persistence

// Flush writes the snapshot and flushes the event archive.
func (s *Store) Flush() error {
	s.mu.Lock()
	if s.evBuf != nil {
		s.evBuf.Flush()
	}
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	snap := snapshot{
		Agents: s.agents, Alerts: s.alerts, Commands: s.commands,
		Inventory: s.inventory, SCA: s.sca, Vulns: s.vulns, Total: s.totalEvents,
	}
	b, err := json.Marshal(snap)
	s.dirty = false
	s.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.dir, "state.json.tmp")
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.dir, "state.json"))
}

// Housekeep prunes histograms and archives older than retentionDays.
func (s *Store) Housekeep(retentionDays int) {
	s.mu.Lock()
	cut := time.Now().Unix()/60 - 60*24*2
	for m := range s.minuteHist {
		if m < cut {
			delete(s.minuteHist, m)
		}
	}
	for m := range s.alertHist {
		if m < cut {
			delete(s.alertHist, m)
		}
	}
	s.mu.Unlock()
	if retentionDays <= 0 {
		return
	}
	files, _ := filepath.Glob(filepath.Join(s.dir, "events", "*.jsonl"))
	limit := time.Now().UTC().AddDate(0, 0, -retentionDays).Format("2006-01-02")
	for _, f := range files {
		if strings.TrimSuffix(filepath.Base(f), ".jsonl") < limit {
			os.Remove(f)
			log.Printf("retention: removed %s", f)
		}
	}
}

func (s *Store) Close() {
	s.Flush()
	s.mu.Lock()
	if s.evFile != nil {
		s.evBuf.Flush()
		s.evFile.Close()
	}
	s.mu.Unlock()
}
