package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vigil-siem/vigil/internal/common"
	"github.com/vigil-siem/vigil/internal/sigma"
)

// ---------------------------------------------------------------- Responder

// AllowedActions are the only commands agents will accept.
var AllowedActions = map[string]string{
	"block_ip":        "Block an IP address in the host firewall (auto-unblocks after timeout)",
	"unblock_ip":      "Remove a firewall block",
	"kill_process":    "Terminate a process by PID",
	"quarantine_file": "Move a file into the agent quarantine directory",
	"restore_file":    "Restore a quarantined file to its original path",
	"run_sca":         "Run the configuration assessment now",
	"run_inventory":   "Collect packages, processes and ports now",
	"run_fim":         "Run a file integrity scan now",
	"restart_agent":   "Restart the agent process",
}

type Responder struct {
	store     *Store
	allowlist []*net.IPNet
	audit     *Audit
}

func NewResponder(store *Store, allow []string, audit *Audit) *Responder {
	r := &Responder{store: store, audit: audit}
	for _, c := range allow {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.Contains(c, "/") {
			if strings.Contains(c, ":") {
				c += "/128"
			} else {
				c += "/32"
			}
		}
		if _, n, err := net.ParseCIDR(c); err == nil {
			r.allowlist = append(r.allowlist, n)
		} else {
			log.Printf("response: bad allowlist entry %q", c)
		}
	}
	return r
}

// Validate checks a command before it is queued.
func (r *Responder) Validate(action string, args map[string]string) error {
	if _, ok := AllowedActions[action]; !ok {
		return fmt.Errorf("unknown action %q", action)
	}
	switch action {
	case "block_ip", "unblock_ip":
		ip := net.ParseIP(args["ip"])
		if ip == nil {
			return fmt.Errorf("invalid ip %q", args["ip"])
		}
		if action == "block_ip" {
			for _, n := range r.allowlist {
				if n.Contains(ip) {
					return fmt.Errorf("ip %s is allowlisted (%s); refusing to block", ip, n)
				}
			}
			if t := args["timeout"]; t != "" {
				if _, err := time.ParseDuration(t); err != nil {
					return fmt.Errorf("bad timeout %q", t)
				}
			}
		}
	case "kill_process":
		pid, err := strconv.Atoi(args["pid"])
		if err != nil || pid <= 1 {
			return fmt.Errorf("invalid pid %q", args["pid"])
		}
	case "quarantine_file", "restore_file":
		p := args["path"]
		if p == "" || !(filepath.IsAbs(p) || (len(p) > 2 && p[1] == ':')) {
			return fmt.Errorf("path must be absolute")
		}
	}
	return nil
}

// Queue validates and queues a command for an agent.
func (r *Responder) Queue(agentID, action string, args map[string]string, by string) (*common.Command, error) {
	if r.store.Agent(agentID) == nil {
		return nil, fmt.Errorf("unknown agent %s", agentID)
	}
	if args == nil {
		args = map[string]string{}
	}
	if err := r.Validate(action, args); err != nil {
		return nil, err
	}
	c := &common.Command{ID: common.NewID(), AgentID: agentID, Action: action, Args: args,
		CreatedAt: time.Now(), UpdatedAt: time.Now(), CreatedBy: by, Status: "pending"}
	r.store.AddCommand(c)
	r.audit.Log(by, "response."+action, agentID, args)
	return c, nil
}

// FromRule builds commands for a rule's `response:` block.
func (r *Responder) FromRule(rule *sigma.Rule, a *common.Alert, fields map[string]string, agentIDs []string) []string {
	args := map[string]string{}
	for arg, field := range rule.Response.ArgFrom {
		v := fields[field]
		if v == "" {
			log.Printf("response: rule %s needs field %s which is empty; skipped", rule.ID, field)
			return nil
		}
		args[arg] = v
	}
	if rule.Response.Timeout != "" {
		args["timeout"] = rule.Response.Timeout
	}
	args["alert_id"] = a.ID
	var ids []string
	for _, ag := range agentIDs {
		if ag == "" || strings.HasPrefix(ag, "syslog:") {
			continue
		}
		c, err := r.Queue(ag, rule.Response.Action, args, "rule:"+rule.ID)
		if err != nil {
			log.Printf("response: %s on %s: %v", rule.Response.Action, ag, err)
			continue
		}
		ids = append(ids, c.ID)
	}
	return ids
}

// ----------------------------------------------------------------- Notifier

// Notifier delivers alerts to a webhook (Slack/Teams/generic JSON) and email.
type Notifier struct {
	cfg    *Config
	client *http.Client
	ch     chan *common.Alert
	min    int
}

func NewNotifier(cfg *Config) *Notifier {
	n := &Notifier{cfg: cfg, client: &http.Client{Timeout: 10 * time.Second},
		ch: make(chan *common.Alert, 1000), min: levelRank[cfg.NotifyLevel]}
	go n.loop()
	return n
}

func (n *Notifier) Notify(a *common.Alert) {
	if levelRank[a.Level] < n.min || (n.cfg.WebhookURL == "" && n.cfg.SMTPHost == "") {
		return
	}
	select {
	case n.ch <- a:
	default:
		log.Printf("notify: queue full, dropping alert %s", a.ID)
	}
}

func (n *Notifier) loop() {
	for a := range n.ch {
		if n.cfg.WebhookURL != "" {
			if err := n.webhook(a); err != nil {
				log.Printf("notify: webhook: %v", err)
			}
		}
		if n.cfg.SMTPHost != "" && n.cfg.SMTPTo != "" {
			if err := n.email(a); err != nil {
				log.Printf("notify: email: %v", err)
			}
		}
	}
}

func (n *Notifier) summary(a *common.Alert) string {
	return fmt.Sprintf("[%s] %s on %s — %s (MITRE: %s)", strings.ToUpper(a.Level), a.RuleTitle, a.Hostname, a.Description, strings.Join(a.MITRE, ","))
}

func (n *Notifier) webhook(a *common.Alert) error {
	body := map[string]any{"text": n.summary(a), "alert": a}
	b, _ := json.Marshal(body)
	resp, err := n.client.Post(n.cfg.WebhookURL, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("status %s", resp.Status)
	}
	return nil
}

func (n *Notifier) email(a *common.Alert) error {
	host, _, _ := net.SplitHostPort(n.cfg.SMTPHost)
	var auth smtp.Auth
	if n.cfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", n.cfg.SMTPUser, n.cfg.SMTPPass, host)
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: Vigil %s alert: %s\r\n\r\n%s\r\n\r\nAgent: %s\r\nTime: %s\r\nCompliance: %s\r\n",
		n.cfg.SMTPFrom, n.cfg.SMTPTo, strings.ToUpper(a.Level), a.RuleTitle, n.summary(a), a.Hostname, a.Timestamp.Format(time.RFC1123), strings.Join(a.Compliance, ", "))
	return smtp.SendMail(n.cfg.SMTPHost, auth, n.cfg.SMTPFrom, strings.Split(n.cfg.SMTPTo, ","), []byte(msg))
}

// ---------------------------------------------------------------------- Hub

// Hub fans out live updates to dashboard Server-Sent-Event subscribers.
type Hub struct {
	mu   sync.Mutex
	subs map[chan []byte]struct{}
}

func NewHub() *Hub { return &Hub{subs: map[chan []byte]struct{}{}} }

func (h *Hub) Subscribe() chan []byte {
	ch := make(chan []byte, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *Hub) Unsubscribe(ch chan []byte) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
}

func (h *Hub) Publish(kind string, v any) {
	b, err := json.Marshal(map[string]any{"type": kind, "data": v})
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- b:
		default: // slow client: drop
		}
	}
}
