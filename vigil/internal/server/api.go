package server

import (
	"compress/gzip"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vigil-siem/vigil/internal/common"
	"github.com/vigil-siem/vigil/web"
)

const Version = "0.1.0"

// Server wires every component together.
type Server struct {
	cfg         *Config
	store       *Store
	engine      *Engine
	auth        *Auth
	audit       *Audit
	responder   *Responder
	hub         *Hub
	vulndb      *VulnDB
	fingerprint string
	enrollMu    sync.Mutex
	enrollFails map[string][]time.Time
}

type ctxUser struct{ name, role string }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	var body io.Reader = http.MaxBytesReader(w, r.Body, int64(s.cfg.MaxBodyMB)<<20)
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(body)
		if err != nil {
			errJSON(w, 400, "bad gzip body")
			return false
		}
		defer gz.Close()
		body = io.LimitReader(gz, int64(s.cfg.MaxBodyMB)<<22)
	}
	if err := json.NewDecoder(body).Decode(v); err != nil {
		errJSON(w, 400, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

// Routes builds the HTTP handler.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// --- agent API (agent bearer token) ---
	mux.HandleFunc("POST /api/agent/enroll", s.handleEnroll)
	mux.HandleFunc("POST /api/agent/events", s.agentAuth(s.handleEvents))
	mux.HandleFunc("POST /api/agent/heartbeat", s.agentAuth(s.handleHeartbeat))
	mux.HandleFunc("POST /api/agent/inventory", s.agentAuth(s.handleInventory))
	mux.HandleFunc("POST /api/agent/sca", s.agentAuth(s.handleSCA))
	mux.HandleFunc("POST /api/agent/command-result", s.agentAuth(s.handleCommandResult))
	mux.HandleFunc("GET /api/agent/config", s.agentAuth(s.handleAgentConfig))

	// --- dashboard API (session token + role) ---
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.user("viewer", s.handleLogout))
	mux.HandleFunc("GET /api/me", s.user("viewer", func(w http.ResponseWriter, r *http.Request, u ctxUser) {
		writeJSON(w, 200, map[string]string{"username": u.name, "role": u.role, "version": Version})
	}))
	mux.HandleFunc("GET /api/stats", s.user("viewer", s.handleStats))
	mux.HandleFunc("GET /api/alerts", s.user("viewer", s.handleAlerts))
	mux.HandleFunc("GET /api/alerts/{id}", s.user("viewer", s.handleAlert))
	mux.HandleFunc("PATCH /api/alerts/{id}", s.user("analyst", s.handleAlertUpdate))
	mux.HandleFunc("POST /api/alerts/bulk", s.user("analyst", s.handleAlertBulk))
	mux.HandleFunc("GET /api/export/alerts.csv", s.user("viewer", s.handleAlertCSV))
	mux.HandleFunc("GET /api/events", s.user("viewer", s.handleEventSearch))
	mux.HandleFunc("GET /api/events/{id}", s.user("viewer", s.handleEvent))
	mux.HandleFunc("GET /api/agents", s.user("viewer", s.handleAgents))
	mux.HandleFunc("GET /api/agents/{id}", s.user("viewer", s.handleAgentDetail))
	mux.HandleFunc("PATCH /api/agents/{id}", s.user("admin", s.handleAgentUpdate))
	mux.HandleFunc("DELETE /api/agents/{id}", s.user("admin", s.handleAgentDelete))
	mux.HandleFunc("GET /api/rules", s.user("viewer", s.handleRules))
	mux.HandleFunc("GET /api/rules/{id}", s.user("viewer", s.handleRuleSource))
	mux.HandleFunc("POST /api/rules", s.user("admin", s.handleRuleSave))
	mux.HandleFunc("PATCH /api/rules/{id}", s.user("admin", s.handleRuleToggle))
	mux.HandleFunc("DELETE /api/rules/{id}", s.user("admin", s.handleRuleDelete))
	mux.HandleFunc("POST /api/rules/test", s.user("analyst", s.handleRuleTest))
	mux.HandleFunc("POST /api/rules/reload", s.user("admin", s.handleRuleReload))
	mux.HandleFunc("GET /api/vulnerabilities", s.user("viewer", s.handleVulns))
	mux.HandleFunc("POST /api/feeds/reload", s.user("admin", s.handleFeedReload))
	mux.HandleFunc("GET /api/compliance", s.user("viewer", s.handleCompliance))
	mux.HandleFunc("GET /api/mitre", s.user("viewer", s.handleMitre))
	mux.HandleFunc("GET /api/commands", s.user("viewer", s.handleCommands))
	mux.HandleFunc("POST /api/commands", s.user("analyst", s.handleCommandCreate))
	mux.HandleFunc("GET /api/actions", s.user("viewer", func(w http.ResponseWriter, r *http.Request, u ctxUser) {
		writeJSON(w, 200, AllowedActions)
	}))
	mux.HandleFunc("GET /api/audit", s.user("admin", func(w http.ResponseWriter, r *http.Request, u ctxUser) {
		writeJSON(w, 200, s.audit.Recent(500))
	}))
	mux.HandleFunc("GET /api/settings", s.user("viewer", s.handleSettings))
	mux.HandleFunc("GET /api/groups", s.user("viewer", s.handleGroups))
	mux.HandleFunc("PUT /api/groups/{name}", s.user("admin", s.handleGroupPut))
	mux.HandleFunc("GET /api/users", s.user("admin", func(w http.ResponseWriter, r *http.Request, u ctxUser) {
		writeJSON(w, 200, s.auth.Users())
	}))
	mux.HandleFunc("POST /api/users", s.user("admin", s.handleUserCreate))
	mux.HandleFunc("DELETE /api/users/{name}", s.user("admin", s.handleUserDelete))
	mux.HandleFunc("GET /api/stream", s.handleStream)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"status": "ok", "version": Version, "processed": s.engine.Processed()})
	})

	// --- dashboard static files ---
	sub, _ := fs.Sub(web.FS, "static")
	files := http.FileServer(http.FS(sub))
	mux.Handle("/", files)

	return s.secure(mux)
}

// secure adds security headers and request logging for errors.
func (s *Server) secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'")
		if s.cfg.TLS {
			hd.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			hd.Set("Cache-Control", "no-store")
		}
		h.ServeHTTP(w, r)
	})
}

func (s *Server) user(minRole string, h func(http.ResponseWriter, *http.Request, ctxUser)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name, role, ok := s.auth.Session(bearer(r))
		if !ok {
			errJSON(w, 401, "authentication required")
			return
		}
		if roleRank[role] < roleRank[minRole] {
			errJSON(w, 403, "requires role "+minRole)
			return
		}
		h(w, r, ctxUser{name, role})
	}
}

func (s *Server) agentAuth(h func(http.ResponseWriter, *http.Request, *common.AgentInfo)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, tok, ok := strings.Cut(bearer(r), ":")
		if !ok {
			errJSON(w, 401, "agent token required")
			return
		}
		a := s.store.Agent(id)
		if a == nil || subtle.ConstantTimeCompare([]byte(TokenHash(tok)), []byte(a.TokenHash)) != 1 {
			errJSON(w, 401, "invalid agent credentials (re-enroll the agent)")
			return
		}
		ip := clientIP(r)
		now := time.Now()
		s.store.UpdateAgent(id, func(x *common.AgentInfo) {
			x.LastSeen = now
			if x.Status != "active" {
				log.Printf("agent %s (%s) is active", x.Name, x.ID)
			}
			x.Status = "active"
			x.IP = ip
		})
		h(w, r, a)
	}
}

// ------------------------------------------------------------- agent API

var reAgentName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	s.enrollMu.Lock()
	var recent []time.Time
	for _, t := range s.enrollFails[ip] {
		if time.Since(t) < 10*time.Minute {
			recent = append(recent, t)
		}
	}
	s.enrollFails[ip] = recent
	s.enrollMu.Unlock()
	if len(recent) >= 10 {
		errJSON(w, 429, "too many failed enrollments")
		return
	}
	var req common.EnrollRequest
	if !s.readJSON(w, r, &req) {
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.EnrollmentKey), []byte(s.cfg.EnrollmentKey)) != 1 {
		s.enrollMu.Lock()
		s.enrollFails[ip] = append(s.enrollFails[ip], time.Now())
		s.enrollMu.Unlock()
		s.audit.Log("system", "agent.enroll_denied", ip, map[string]string{"name": req.Name})
		errJSON(w, 403, "invalid enrollment key")
		return
	}
	if req.Name == "" {
		req.Name = req.Hostname
	}
	if !reAgentName.MatchString(req.Name) {
		errJSON(w, 400, "agent name must match [A-Za-z0-9._-]{1,64}")
		return
	}
	if req.Group == "" {
		req.Group = "default"
	}
	// Re-enrolling the same name replaces the old identity (e.g. reinstall).
	for _, a := range s.store.Agents() {
		if a.Name == req.Name && !strings.HasPrefix(a.ID, "syslog:") {
			s.store.DeleteAgent(a.ID)
			s.audit.Log("system", "agent.replaced", a.ID, map[string]string{"name": a.Name})
		}
	}
	tok := common.RandomToken(32)
	a := &common.AgentInfo{
		ID: common.NewID()[:16], Name: req.Name, Hostname: req.Hostname, OS: req.OS, Arch: req.Arch,
		IP: ip, Version: req.Version, Group: req.Group, EnrolledAt: time.Now(), LastSeen: time.Now(),
		Status: "active", TokenHash: TokenHash(tok),
	}
	s.store.PutAgent(a)
	s.audit.Log("system", "agent.enrolled", a.ID, map[string]string{"name": a.Name, "ip": ip, "os": a.OS})
	log.Printf("agent enrolled: %s (%s) from %s", a.Name, a.ID, ip)
	s.hub.Publish("agent", a.ID)
	writeJSON(w, 200, common.EnrollResponse{AgentID: a.ID, Token: tok})
}

var allowedCategories = map[string]bool{"log": true, "fim": true, "process": true, "network": true, "sca": true, "inventory": true, "response": true, "agent": true}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, a *common.AgentInfo) {
	var batch common.EventBatch
	if !s.readJSON(w, r, &batch) {
		return
	}
	if len(batch.Events) > 10000 {
		errJSON(w, 413, "max 10000 events per batch")
		return
	}
	now := time.Now()
	evs := make([]*common.Event, 0, len(batch.Events))
	for i := range batch.Events {
		e := &batch.Events[i]
		// identity always comes from the token, never from the payload
		e.AgentID, e.Hostname = a.ID, a.Name
		if e.ID == "" {
			e.ID = common.NewID()
		}
		if e.Timestamp.IsZero() || e.Timestamp.After(now.Add(5*time.Minute)) {
			e.Timestamp = now
		}
		if !allowedCategories[e.Category] {
			e.Category = "log"
		}
		if len(e.Raw) > 32*1024 {
			e.Raw = e.Raw[:32*1024]
		}
		if e.Fields == nil {
			e.Fields = map[string]string{}
		}
		if len(e.Fields) > 256 {
			continue
		}
		for k, v := range e.Fields {
			if len(v) > 8192 {
				e.Fields[k] = v[:8192]
			}
		}
		if _, ok := e.Fields["os.type"]; !ok {
			e.Fields["os.type"] = a.OS
		}
		e.Fields["agent.name"] = a.Name
		evs = append(evs, e)
	}
	s.engine.Ingest(evs)
	writeJSON(w, 200, map[string]int{"accepted": len(evs)})
}

func (s *Server) groupConfig(group string) (string, int) {
	b, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "groups", group+".yml"))
	if err != nil {
		return "", 0
	}
	sum := sha256.Sum256(b)
	v, _ := strconv.ParseInt(hex.EncodeToString(sum[:3]), 16, 64)
	return string(b), int(v) + 1
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request, a *common.AgentInfo) {
	var hb common.HeartbeatRequest
	if !s.readJSON(w, r, &hb) {
		return
	}
	s.store.UpdateAgent(a.ID, func(x *common.AgentInfo) {
		x.Health = hb
		if hb.Version != "" {
			x.Version = hb.Version
		}
	})
	_, ver := s.groupConfig(a.Group)
	writeJSON(w, 200, common.HeartbeatResponse{Commands: s.store.TakePending(a.ID), ServerTime: time.Now(), ConfigVersion: ver})
}

func (s *Server) handleAgentConfig(w http.ResponseWriter, r *http.Request, a *common.AgentInfo) {
	y, ver := s.groupConfig(a.Group)
	writeJSON(w, 200, map[string]any{"version": ver, "group": a.Group, "yaml": y})
}

var vulnLevel = map[string]string{"critical": "critical", "high": "high", "medium": "medium", "low": "low"}

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request, a *common.AgentInfo) {
	var inv common.Inventory
	if !s.readJSON(w, r, &inv) {
		return
	}
	inv.AgentID = a.ID
	if inv.Timestamp.IsZero() {
		inv.Timestamp = time.Now()
	}
	s.store.PutInventory(&inv)
	findings := s.vulndb.Scan(&inv, a.Name)
	fresh := s.store.PutVulns(a.ID, findings)
	for _, f := range fresh {
		lvl := vulnLevel[strings.ToLower(f.Severity)]
		if lvl == "" {
			lvl = "medium"
		}
		s.engine.SystemAlert("vulnerability", "vuln:"+f.CVE, f.CVE+" in "+f.Package, lvl, a,
			fmt.Sprintf("%s %s is affected by %s (CVSS %.1f, fixed in %s): %s", f.Package, f.Version, f.CVE, f.CVSS, orDash(f.Fixed), f.Summary),
			[]string{"attack.initial-access", "attack.privilege-escalation"},
			map[string]string{"vulnerability.id": f.CVE, "package.name": f.Package, "package.version": f.Version, "package.fixed_version": f.Fixed, "vulnerability.score": fmt.Sprint(f.CVSS)},
			"vuln|"+a.ID+"|"+f.CVE+"|"+f.Package, nil)
	}
	writeJSON(w, 200, map[string]int{"packages": len(inv.Packages), "vulnerabilities": len(findings)})
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (s *Server) handleSCA(w http.ResponseWriter, r *http.Request, a *common.AgentInfo) {
	var rep common.SCAReport
	if !s.readJSON(w, r, &rep) {
		return
	}
	rep.AgentID = a.ID
	if rep.Timestamp.IsZero() {
		rep.Timestamp = time.Now()
	}
	prev := s.store.PutSCA(&rep)
	prevFailed := map[string]bool{}
	if prev != nil {
		for _, c := range prev.Results {
			if c.Result == "failed" {
				prevFailed[c.CheckID] = true
			}
		}
	}
	for _, c := range rep.Results {
		if c.Result != "failed" || prevFailed[c.CheckID] {
			continue
		}
		s.engine.SystemAlert("sca", "sca:"+c.CheckID, "SCA failed: "+c.Title, "low", a,
			c.Rationale+" Remediation: "+c.Remedy, nil,
			map[string]string{"sca.check_id": c.CheckID, "sca.policy": rep.Policy, "sca.result": c.Result},
			"sca|"+a.ID+"|"+c.CheckID, c.Compliance)
	}
	writeJSON(w, 200, map[string]int{"score": scaScore(&rep)})
}

func (s *Server) handleCommandResult(w http.ResponseWriter, r *http.Request, a *common.AgentInfo) {
	var res common.CommandResult
	if !s.readJSON(w, r, &res) {
		return
	}
	if !s.store.CompleteCommand(a.ID, res) {
		errJSON(w, 404, "unknown command")
		return
	}
	s.audit.Log("agent:"+a.Name, "response.result", res.CommandID, map[string]string{"status": res.Status, "output": trunc(res.Output, 300)})
	s.hub.Publish("command", res)
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

// --------------------------------------------------------- dashboard API

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password string }
	if !s.readJSON(w, r, &req) {
		return
	}
	tok, u, err := s.auth.Login(req.Username, req.Password, clientIP(r))
	if err != nil {
		s.audit.Log(req.Username, "auth.login_failed", clientIP(r), nil)
		code := 401
		if err == errThrottled {
			code = 429
		}
		errJSON(w, code, err.Error())
		return
	}
	s.audit.Log(u.Username, "auth.login", clientIP(r), nil)
	writeJSON(w, 200, map[string]string{"token": tok, "username": u.Username, "role": u.Role})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, u ctxUser) {
	s.auth.Logout(bearer(r))
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request, u ctxUser) {
	since := time.Now().Add(-24 * time.Hour)
	if h, err := strconv.Atoi(r.URL.Query().Get("hours")); err == nil && h > 0 {
		since = time.Now().Add(-time.Duration(h) * time.Hour)
	}
	st := s.store.Stats(since)
	rules, _ := s.engine.RuleInfos()
	writeJSON(w, 200, map[string]any{"stats": st, "rules": len(rules), "cves": s.vulndb.Count(), "processed": s.engine.Processed()})
}

func atoiDef(s string, d int) int {
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return n
	}
	return d
}

func (s *Server) alertFilter(r *http.Request) func(*common.Alert) bool {
	q := r.URL.Query()
	levels := map[string]bool{}
	for _, l := range strings.Split(q.Get("level"), ",") {
		if l != "" {
			levels[l] = true
		}
	}
	minLvl := q.Get("min_level")
	status, agent, kind, rule := q.Get("status"), q.Get("agent"), q.Get("kind"), q.Get("rule")
	text := strings.ToLower(q.Get("q"))
	var since time.Time
	if h := atoiDef(q.Get("hours"), 0); h > 0 {
		since = time.Now().Add(-time.Duration(h) * time.Hour)
	}
	return func(a *common.Alert) bool {
		if len(levels) > 0 && !levels[a.Level] {
			return false
		}
		if minLvl != "" && levelRank[a.Level] < levelRank[minLvl] {
			return false
		}
		if status != "" && a.Status != status {
			return false
		}
		if agent != "" && a.AgentID != agent && a.Hostname != agent {
			return false
		}
		if kind != "" && a.Kind != kind {
			return false
		}
		if rule != "" && a.RuleID != rule {
			return false
		}
		if !since.IsZero() && a.LastSeen.Before(since) {
			return false
		}
		if text != "" {
			hay := strings.ToLower(a.RuleTitle + " " + a.Description + " " + a.Hostname + " " + strings.Join(a.MITRE, " ") + " " + strings.Join(a.Tags, " "))
			for _, v := range a.Fields {
				hay += " " + strings.ToLower(v)
			}
			if !strings.Contains(hay, text) {
				return false
			}
		}
		return true
	}
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request, u ctxUser) {
	limit := atoiDef(r.URL.Query().Get("limit"), 200)
	if limit > 5000 {
		limit = 5000
	}
	writeJSON(w, 200, s.store.Alerts(s.alertFilter(r), limit))
}

func (s *Server) eventsByID(ids []string) []*common.Event {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	return s.store.RecentEvents(len(ids), func(e *common.Event) bool { return want[e.ID] })
}

func (s *Server) handleAlert(w http.ResponseWriter, r *http.Request, u ctxUser) {
	a := s.store.Alert(r.PathValue("id"))
	if a == nil {
		errJSON(w, 404, "not found")
		return
	}
	var cmds []*common.Command
	if a.Response != "" {
		ids := strings.Split(a.Response, ",")
		for _, c := range s.store.Commands(5000) {
			for _, id := range ids {
				if c.ID == id {
					cmds = append(cmds, c)
				}
			}
		}
	}
	writeJSON(w, 200, map[string]any{"alert": a, "events": s.eventsByID(a.EventIDs), "commands": cmds})
}

func (s *Server) handleAlertUpdate(w http.ResponseWriter, r *http.Request, u ctxUser) {
	var req struct {
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if !s.readJSON(w, r, &req) {
		return
	}
	if req.Status != "" && req.Status != "open" && req.Status != "acknowledged" && req.Status != "closed" {
		errJSON(w, 400, "status must be open, acknowledged or closed")
		return
	}
	id := r.PathValue("id")
	ok := s.store.UpdateAlert(id, func(a *common.Alert) {
		if req.Status != "" {
			a.Status = req.Status
		}
		if req.Note != "" {
			a.Note = strings.TrimSpace(a.Note + "\n[" + time.Now().Format("2006-01-02 15:04") + " " + u.name + "] " + req.Note)
		}
	})
	if !ok {
		errJSON(w, 404, "not found")
		return
	}
	s.audit.Log(u.name, "alert.update", id, map[string]string{"status": req.Status})
	writeJSON(w, 200, s.store.Alert(id))
}

func (s *Server) handleAlertBulk(w http.ResponseWriter, r *http.Request, u ctxUser) {
	var req struct {
		IDs    []string `json:"ids"`
		Status string   `json:"status"`
	}
	if !s.readJSON(w, r, &req) {
		return
	}
	if req.Status != "open" && req.Status != "acknowledged" && req.Status != "closed" {
		errJSON(w, 400, "bad status")
		return
	}
	n := 0
	for _, id := range req.IDs {
		if s.store.UpdateAlert(id, func(a *common.Alert) { a.Status = req.Status }) {
			n++
		}
	}
	s.audit.Log(u.name, "alert.bulk_update", fmt.Sprintf("%d alerts", n), map[string]string{"status": req.Status})
	writeJSON(w, 200, map[string]int{"updated": n})
}

func (s *Server) handleAlertCSV(w http.ResponseWriter, r *http.Request, u ctxUser) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=vigil-alerts.csv")
	cw := csv.NewWriter(w)
	cw.Write([]string{"time", "last_seen", "level", "rule_id", "rule", "host", "kind", "status", "count", "mitre", "compliance", "description"})
	for _, a := range s.store.Alerts(s.alertFilter(r), 100000) {
		cw.Write([]string{a.Timestamp.Format(time.RFC3339), a.LastSeen.Format(time.RFC3339), a.Level, a.RuleID, a.RuleTitle, a.Hostname, a.Kind, a.Status,
			strconv.Itoa(a.Count), strings.Join(a.MITRE, " "), strings.Join(a.Compliance, "; "), csvSafe(a.Description)})
	}
	cw.Flush()
	s.audit.Log(u.name, "alert.export", "csv", nil)
}

// csvSafe neutralises spreadsheet formula injection.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

func (s *Server) handleEventSearch(w http.ResponseWriter, r *http.Request, u ctxUser) {
	q := r.URL.Query()
	limit := atoiDef(q.Get("limit"), 200)
	if limit > 2000 {
		limit = 2000
	}
	match := ParseQuery(q.Get("q"))
	agent, cat := q.Get("agent"), q.Get("category")
	var from, to time.Time
	if v := q.Get("from"); v != "" {
		from, _ = time.Parse(time.RFC3339, v)
	}
	if v := q.Get("to"); v != "" {
		to, _ = time.Parse(time.RFC3339, v)
	}
	if h := atoiDef(q.Get("hours"), 0); h > 0 {
		from = time.Now().Add(-time.Duration(h) * time.Hour)
	}
	filter := func(e *common.Event) bool {
		if agent != "" && e.AgentID != agent && e.Hostname != agent {
			return false
		}
		if cat != "" && e.Category != cat {
			return false
		}
		if !from.IsZero() && e.Timestamp.Before(from) {
			return false
		}
		if !to.IsZero() && e.Timestamp.After(to) {
			return false
		}
		return match(e)
	}
	start := time.Now()
	res := s.store.RecentEvents(limit, filter)
	source := "memory"
	// fall back to the on-disk archive when the range is older than memory
	if len(res) < limit && !from.IsZero() && from.Before(s.store.OldestInMemory()) {
		source = "memory+archive"
		end := s.store.OldestInMemory()
		if !to.IsZero() && to.Before(end) {
			end = to
		}
		var older []*common.Event
		s.store.ArchiveScan(from, end, func(e *common.Event) bool {
			if e.Timestamp.Before(end) && filter(e) {
				older = append(older, e)
			}
			return len(older) < 50000
		})
		sort.Slice(older, func(i, j int) bool { return older[i].Timestamp.After(older[j].Timestamp) })
		for _, e := range older {
			if len(res) >= limit {
				break
			}
			res = append(res, e)
		}
	}
	writeJSON(w, 200, map[string]any{"events": res, "took_ms": time.Since(start).Milliseconds(), "source": source})
}

func (s *Server) handleEvent(w http.ResponseWriter, r *http.Request, u ctxUser) {
	evs := s.eventsByID([]string{r.PathValue("id")})
	if len(evs) == 0 {
		errJSON(w, 404, "not found (may have aged out of memory)")
		return
	}
	writeJSON(w, 200, evs[0])
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request, u ctxUser) {
	writeJSON(w, 200, s.store.Agents())
}

func (s *Server) handleAgentDetail(w http.ResponseWriter, r *http.Request, u ctxUser) {
	id := r.PathValue("id")
	a := s.store.Agent(id)
	if a == nil {
		errJSON(w, 404, "not found")
		return
	}
	cp := *a
	cp.TokenHash = ""
	alerts := s.store.Alerts(func(x *common.Alert) bool { return x.AgentID == id }, 50)
	writeJSON(w, 200, map[string]any{"agent": cp, "inventory": s.store.Inventory(id), "sca": s.store.SCA(id),
		"vulnerabilities": s.store.Vulns(id), "alerts": alerts})
}

func (s *Server) handleAgentUpdate(w http.ResponseWriter, r *http.Request, u ctxUser) {
	var req struct {
		Group string `json:"group"`
	}
	if !s.readJSON(w, r, &req) {
		return
	}
	if !reAgentName.MatchString(req.Group) {
		errJSON(w, 400, "invalid group name")
		return
	}
	id := r.PathValue("id")
	if !s.store.UpdateAgent(id, func(a *common.AgentInfo) { a.Group = req.Group }) {
		errJSON(w, 404, "not found")
		return
	}
	s.audit.Log(u.name, "agent.group", id, map[string]string{"group": req.Group})
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) handleAgentDelete(w http.ResponseWriter, r *http.Request, u ctxUser) {
	id := r.PathValue("id")
	if s.store.Agent(id) == nil {
		errJSON(w, 404, "not found")
		return
	}
	s.store.DeleteAgent(id)
	s.audit.Log(u.name, "agent.delete", id, nil)
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request, u ctxUser) {
	rules, errs := s.engine.RuleInfos()
	writeJSON(w, 200, map[string]any{"rules": rules, "errors": errs})
}

func (s *Server) handleRuleSource(w http.ResponseWriter, r *http.Request, u ctxUser) {
	src, ok := s.engine.RuleSource(r.PathValue("id"))
	if !ok {
		errJSON(w, 404, "not found")
		return
	}
	writeJSON(w, 200, map[string]string{"source": src})
}

func readText(w http.ResponseWriter, r *http.Request) (string, bool) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256*1024))
	if err != nil {
		errJSON(w, 400, "body too large")
		return "", false
	}
	var wrapped struct {
		Source string `json:"source"`
	}
	if json.Unmarshal(b, &wrapped) == nil && wrapped.Source != "" {
		return wrapped.Source, true
	}
	return string(b), true
}

func (s *Server) handleRuleSave(w http.ResponseWriter, r *http.Request, u ctxUser) {
	src, ok := readText(w, r)
	if !ok {
		return
	}
	rule, err := s.engine.SaveCustomRule(src)
	if err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	s.audit.Log(u.name, "rule.save", rule.ID, map[string]string{"title": rule.Title})
	writeJSON(w, 200, map[string]string{"id": rule.ID, "title": rule.Title})
}

func (s *Server) handleRuleToggle(w http.ResponseWriter, r *http.Request, u ctxUser) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !s.readJSON(w, r, &req) {
		return
	}
	id := r.PathValue("id")
	if !s.engine.SetEnabled(id, req.Enabled) {
		errJSON(w, 404, "not found")
		return
	}
	s.audit.Log(u.name, "rule.toggle", id, map[string]string{"enabled": strconv.FormatBool(req.Enabled)})
	writeJSON(w, 200, map[string]bool{"enabled": req.Enabled})
}

func (s *Server) handleRuleDelete(w http.ResponseWriter, r *http.Request, u ctxUser) {
	id := r.PathValue("id")
	if err := s.engine.DeleteCustomRule(id); err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	s.audit.Log(u.name, "rule.delete", id, nil)
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}

func (s *Server) handleRuleTest(w http.ResponseWriter, r *http.Request, u ctxUser) {
	src, ok := readText(w, r)
	if !ok {
		return
	}
	limit := atoiDef(r.URL.Query().Get("events"), 50000)
	evs, scanned, err := s.engine.TestRule(src, limit)
	if err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"matches": evs, "count": len(evs), "scanned": scanned})
}

func (s *Server) handleRuleReload(w http.ResponseWriter, r *http.Request, u ctxUser) {
	s.engine.LoadRules()
	rules, errs := s.engine.RuleInfos()
	s.audit.Log(u.name, "rule.reload", "", nil)
	writeJSON(w, 200, map[string]any{"rules": len(rules), "errors": errs})
}

func (s *Server) handleVulns(w http.ResponseWriter, r *http.Request, u ctxUser) {
	writeJSON(w, 200, map[string]any{"findings": s.store.Vulns(r.URL.Query().Get("agent")), "feed_entries": s.vulndb.Count()})
}

func (s *Server) handleFeedReload(w http.ResponseWriter, r *http.Request, u ctxUser) {
	if err := s.vulndb.LoadDir(s.cfg.FeedsDir); err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	s.audit.Log(u.name, "feed.reload", s.cfg.FeedsDir, nil)
	writeJSON(w, 200, map[string]int{"entries": s.vulndb.Count()})
}

func (s *Server) handleCompliance(w http.ResponseWriter, r *http.Request, u ctxUser) {
	hours := atoiDef(r.URL.Query().Get("hours"), 24*30)
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	alerts := s.store.Alerts(func(a *common.Alert) bool { return !a.LastSeen.Before(since) }, 100000)
	type agentSCA struct {
		AgentID string             `json:"agent_id"`
		Name    string             `json:"name"`
		Score   int                `json:"score"`
		Policy  string             `json:"policy"`
		Failed  []common.SCAResult `json:"failed"`
		Passed  int                `json:"passed"`
		Total   int                `json:"total"`
		When    time.Time          `json:"when"`
	}
	var scas []agentSCA
	for id, rep := range s.store.AllSCA() {
		a := s.store.Agent(id)
		if a == nil {
			continue
		}
		as := agentSCA{AgentID: id, Name: a.Name, Score: scaScore(rep), Policy: rep.Policy, When: rep.Timestamp}
		for _, c := range rep.Results {
			if c.Result == "not_applicable" {
				continue
			}
			as.Total++
			if c.Result == "passed" {
				as.Passed++
			} else {
				as.Failed = append(as.Failed, c)
			}
		}
		scas = append(scas, as)
	}
	sort.Slice(scas, func(i, j int) bool { return scas[i].Name < scas[j].Name })
	writeJSON(w, 200, map[string]any{"frameworks": BuildCompliance(alerts), "sca": scas})
}

func (s *Server) handleMitre(w http.ResponseWriter, r *http.Request, u ctxUser) {
	hours := atoiDef(r.URL.Query().Get("hours"), 24*7)
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	alerts := s.store.Alerts(func(a *common.Alert) bool { return !a.LastSeen.Before(since) }, 100000)
	writeJSON(w, 200, BuildMitre(alerts))
}

func (s *Server) handleCommands(w http.ResponseWriter, r *http.Request, u ctxUser) {
	writeJSON(w, 200, s.store.Commands(500))
}

func (s *Server) handleCommandCreate(w http.ResponseWriter, r *http.Request, u ctxUser) {
	var req struct {
		AgentID string            `json:"agent_id"`
		Action  string            `json:"action"`
		Args    map[string]string `json:"args"`
	}
	if !s.readJSON(w, r, &req) {
		return
	}
	c, err := s.responder.Queue(req.AgentID, req.Action, req.Args, u.name)
	if err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, c)
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request, u ctxUser) {
	out := map[string]any{
		"version": Version, "tls": s.cfg.TLS, "fingerprint": s.fingerprint, "listen": s.cfg.Listen,
		"syslog": s.cfg.SyslogListen, "min_alert_level": s.cfg.MinAlertLevel, "notify_level": s.cfg.NotifyLevel,
		"webhook": s.cfg.WebhookURL != "", "email": s.cfg.SMTPHost != "", "auto_response": s.cfg.AutoResponse,
		"response_allowlist": s.cfg.ResponseAllowlist, "retention_days": s.cfg.RetentionDays,
		"max_events": s.cfg.MaxEvents, "feed_entries": s.vulndb.Count(),
	}
	if u.role == "admin" {
		out["enrollment_key"] = s.cfg.EnrollmentKey
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request, u ctxUser) {
	groups := map[string]int{"default": 0}
	for _, a := range s.store.Agents() {
		groups[a.Group]++
	}
	files, _ := filepath.Glob(filepath.Join(s.cfg.DataDir, "groups", "*.yml"))
	for _, f := range files {
		g := strings.TrimSuffix(filepath.Base(f), ".yml")
		if _, ok := groups[g]; !ok {
			groups[g] = 0
		}
	}
	var out []map[string]any
	for g, n := range groups {
		y, v := s.groupConfig(g)
		out = append(out, map[string]any{"name": g, "agents": n, "config": y, "version": v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["name"].(string) < out[j]["name"].(string) })
	writeJSON(w, 200, out)
}

func (s *Server) handleGroupPut(w http.ResponseWriter, r *http.Request, u ctxUser) {
	name := r.PathValue("name")
	if !reAgentName.MatchString(name) {
		errJSON(w, 400, "invalid group name")
		return
	}
	src, ok := readText(w, r)
	if !ok {
		return
	}
	if err := validateAgentConfig(src); err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	dir := filepath.Join(s.cfg.DataDir, "groups")
	os.MkdirAll(dir, 0o750)
	if err := os.WriteFile(filepath.Join(dir, name+".yml"), []byte(src), 0o640); err != nil {
		errJSON(w, 500, err.Error())
		return
	}
	s.audit.Log(u.name, "group.config", name, nil)
	_, v := s.groupConfig(name)
	writeJSON(w, 200, map[string]int{"version": v})
}

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request, u ctxUser) {
	var req struct{ Username, Password, Role string }
	if !s.readJSON(w, r, &req) {
		return
	}
	if err := s.auth.CreateUser(req.Username, req.Password, req.Role); err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	s.audit.Log(u.name, "user.create", req.Username, map[string]string{"role": req.Role})
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request, u ctxUser) {
	name := r.PathValue("name")
	if err := s.auth.DeleteUser(name); err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	s.audit.Log(u.name, "user.delete", name, nil)
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

// handleStream is a Server-Sent-Events feed; EventSource can't send headers,
// so the session token comes as a query parameter.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.auth.Session(r.URL.Query().Get("token")); !ok {
		errJSON(w, 401, "authentication required")
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		errJSON(w, 500, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	ch := s.hub.Subscribe()
	defer s.hub.Unsubscribe(ch)
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	fmt.Fprint(w, ": connected\n\n")
	fl.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case b := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", b)
			fl.Flush()
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
	}
}
