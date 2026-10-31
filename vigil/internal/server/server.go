package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vigil-siem/vigil/internal/common"
	"github.com/vigil-siem/vigil/internal/yamlite"
)

// New builds a server from config.
func New(cfg *Config) (*Server, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return nil, err
	}
	if cfg.EnrollmentKey == "" {
		p := filepath.Join(cfg.DataDir, "enrollment.key")
		if b, err := os.ReadFile(p); err == nil {
			cfg.EnrollmentKey = strings.TrimSpace(string(b))
		} else {
			cfg.EnrollmentKey = common.RandomToken(16)
			if err := os.WriteFile(p, []byte(cfg.EnrollmentKey+"\n"), 0o600); err != nil {
				return nil, err
			}
		}
	}
	store, err := NewStore(cfg.DataDir, cfg.MaxEvents, cfg.MaxAlerts)
	if err != nil {
		return nil, err
	}
	audit, err := NewAudit(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	auth, err := NewAuth(cfg.DataDir, cfg.AdminPassword)
	if err != nil {
		return nil, err
	}
	hub := NewHub()
	resp := NewResponder(store, cfg.ResponseAllowlist, audit)
	eng := NewEngine(cfg, store, NewNotifier(cfg), resp, hub)
	if err := eng.LoadRules(); err != nil {
		return nil, err
	}
	vdb := NewVulnDB()
	if err := vdb.LoadDir(cfg.FeedsDir); err != nil {
		log.Printf("vuln feed: %v", err)
	}
	log.Printf("vuln feed: %d CVE entries", vdb.Count())
	return &Server{cfg: cfg, store: store, engine: eng, auth: auth, audit: audit,
		responder: resp, hub: hub, vulndb: vdb, enrollFails: map[string][]time.Time{}}, nil
}

// Run starts listeners and background jobs until SIGINT/SIGTERM.
func (s *Server) Run() error {
	srv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	var cert, key string
	if s.cfg.TLS {
		var err error
		cert, key, err = EnsureCert(s.cfg)
		if err != nil {
			return fmt.Errorf("tls: %w", err)
		}
		s.fingerprint, err = CertFingerprint(cert, key)
		if err != nil {
			return fmt.Errorf("tls: %w", err)
		}
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	StartSyslog(s.cfg.SyslogListen, s.engine, s.store)
	go s.background()

	scheme := "http"
	if s.cfg.TLS {
		scheme = "https"
	}
	log.Printf("vigil-server %s listening on %s://%s", Version, scheme, s.cfg.Listen)
	log.Printf("enrollment key: %s", s.cfg.EnrollmentKey)
	if s.fingerprint != "" {
		log.Printf("tls fingerprint (pin this in agents): %s", s.fingerprint)
	}

	errc := make(chan error, 1)
	go func() {
		if s.cfg.TLS {
			errc <- srv.ListenAndServeTLS(cert, key)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errc:
		s.store.Close()
		return err
	case <-sig:
		log.Printf("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		s.store.Close()
		return nil
	}
}

func (s *Server) background() {
	flush := time.NewTicker(5 * time.Second)
	health := time.NewTicker(15 * time.Second)
	house := time.NewTicker(time.Hour)
	s.store.Housekeep(s.cfg.RetentionDays)
	for {
		select {
		case <-flush.C:
			if err := s.store.Flush(); err != nil {
				log.Printf("store flush: %v", err)
			}
		case <-health.C:
			s.checkAgents()
			s.engine.GC()
		case <-house.C:
			s.store.Housekeep(s.cfg.RetentionDays)
		}
	}
}

// checkAgents marks silent agents disconnected and alerts on it: an agent
// that stops reporting may have been stopped by an attacker (T1562.001).
func (s *Server) checkAgents() {
	now := time.Now()
	for _, a := range s.store.Agents() {
		if a.Status != "active" || now.Sub(a.LastSeen) < s.cfg.AgentTimeout {
			continue
		}
		s.store.UpdateAgent(a.ID, func(x *common.AgentInfo) { x.Status = "disconnected" })
		s.hub.Publish("agent", a.ID)
		if strings.HasPrefix(a.ID, "syslog:") {
			continue
		}
		log.Printf("agent %s (%s) disconnected", a.Name, a.ID)
		s.engine.SystemAlert("system", "agent-disconnected", "Agent stopped reporting", "medium", a,
			fmt.Sprintf("No heartbeat from %s for %s (last seen %s)", a.Name, now.Sub(a.LastSeen).Round(time.Second), a.LastSeen.Format(time.RFC3339)),
			[]string{"attack.defense-evasion", "attack.t1562.001"}, map[string]string{"agent.name": a.Name, "agent.ip": a.IP},
			"disconnected|"+a.ID+"|"+a.LastSeen.Format(time.RFC3339), nil)
	}
}

// validateAgentConfig checks that a group config is a YAML map with known keys.
func validateAgentConfig(src string) error {
	v, err := yamlite.Parse(src)
	if err != nil {
		return err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("config must be a YAML map")
	}
	known := map[string]bool{"logs": true, "fim": true, "intervals": true, "sca": true, "active_response": true, "processes": true, "inventory": true, "windows_eventlog": true}
	for k := range m {
		if !known[k] {
			return fmt.Errorf("unknown key %q (allowed: logs, fim, intervals, sca, active_response, processes, inventory, windows_eventlog)", k)
		}
	}
	return nil
}
