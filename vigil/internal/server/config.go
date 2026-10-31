package server

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vigil-siem/vigil/internal/yamlite"
)

// Config holds server settings. Precedence: flags > env (VIGIL_*) > config file > defaults.
type Config struct {
	Listen            string
	DataDir           string
	RulesDir          string
	FeedsDir          string
	SCAPolicyDir      string
	TLS               bool
	CertFile          string
	KeyFile           string
	EnrollmentKey     string
	AdminPassword     string
	SyslogListen      string
	MinAlertLevel     string
	NotifyLevel       string
	WebhookURL        string
	SMTPHost          string
	SMTPUser          string
	SMTPPass          string
	SMTPFrom          string
	SMTPTo            string
	AutoResponse      bool
	ResponseAllowlist []string
	RetentionDays     int
	MaxEvents         int
	MaxAlerts         int
	DedupWindow       time.Duration
	AgentTimeout      time.Duration
	MaxBodyMB         int
}

func DefaultConfig() *Config {
	return &Config{
		Listen: ":8443", DataDir: "./data", RulesDir: "./rules", FeedsDir: "./feeds", SCAPolicyDir: "./sca",
		TLS: true, SyslogListen: ":5514", MinAlertLevel: "low", NotifyLevel: "high",
		AutoResponse: true, ResponseAllowlist: []string{"127.0.0.0/8", "::1"},
		RetentionDays: 30, MaxEvents: 200000, MaxAlerts: 50000,
		DedupWindow: 60 * time.Second, AgentTimeout: 90 * time.Second, MaxBodyMB: 16,
	}
}

// LoadConfig parses flags, env and an optional YAML config file.
func LoadConfig(args []string) (*Config, error) {
	c := DefaultConfig()
	fs := flag.NewFlagSet("vigil-server", flag.ContinueOnError)
	cfgFile := fs.String("config", os.Getenv("VIGIL_CONFIG"), "path to server.yml")
	listen := fs.String("listen", "", "HTTPS listen address (default :8443)")
	dataDir := fs.String("data", "", "data directory")
	rulesDir := fs.String("rules", "", "Sigma rules directory")
	noTLS := fs.Bool("no-tls", false, "serve plain HTTP (development only)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if *cfgFile != "" {
		b, err := os.ReadFile(*cfgFile)
		if err != nil {
			return nil, err
		}
		v, err := yamlite.Parse(string(b))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", *cfgFile, err)
		}
		if m, ok := v.(map[string]any); ok {
			for k, val := range m {
				if err := c.set(k, val); err != nil {
					return nil, err
				}
			}
		}
	}
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "VIGIL_") && k != "VIGIL_CONFIG" {
			key := strings.ToLower(strings.TrimPrefix(k, "VIGIL_"))
			if err := c.set(key, v); err != nil {
				return nil, fmt.Errorf("env %s: %w", k, err)
			}
		}
	}
	if *listen != "" {
		c.Listen = *listen
	}
	if *dataDir != "" {
		c.DataDir = *dataDir
	}
	if *rulesDir != "" {
		c.RulesDir = *rulesDir
	}
	if *noTLS {
		c.TLS = false
	}
	if _, ok := levelRank[c.MinAlertLevel]; !ok {
		return nil, fmt.Errorf("min_alert_level must be informational|low|medium|high|critical")
	}
	if _, ok := levelRank[c.NotifyLevel]; !ok {
		return nil, fmt.Errorf("notify_level must be informational|low|medium|high|critical")
	}
	return c, nil
}

func (c *Config) set(key string, v any) error {
	s := ""
	switch x := v.(type) {
	case string:
		s = x
	case []any:
		for _, e := range x {
			s += fmt.Sprint(e) + ","
		}
		s = strings.TrimSuffix(s, ",")
	case nil:
	default:
		s = fmt.Sprint(x)
	}
	b := func() bool { return s == "true" || s == "yes" || s == "1" || s == "on" }
	n := func() (int, error) { return strconv.Atoi(s) }
	var err error
	switch strings.ReplaceAll(key, "-", "_") {
	case "listen":
		c.Listen = s
	case "data_dir":
		c.DataDir = s
	case "rules_dir":
		c.RulesDir = s
	case "feeds_dir":
		c.FeedsDir = s
	case "sca_policy_dir":
		c.SCAPolicyDir = s
	case "tls":
		c.TLS = b()
	case "cert_file":
		c.CertFile = s
	case "key_file":
		c.KeyFile = s
	case "enrollment_key":
		c.EnrollmentKey = s
	case "admin_password":
		c.AdminPassword = s
	case "syslog_listen":
		c.SyslogListen = s
	case "min_alert_level":
		c.MinAlertLevel = s
	case "notify_level":
		c.NotifyLevel = s
	case "webhook_url":
		c.WebhookURL = s
	case "smtp_host":
		c.SMTPHost = s
	case "smtp_user":
		c.SMTPUser = s
	case "smtp_pass":
		c.SMTPPass = s
	case "smtp_from":
		c.SMTPFrom = s
	case "smtp_to":
		c.SMTPTo = s
	case "auto_response":
		c.AutoResponse = b()
	case "response_allowlist":
		c.ResponseAllowlist = strings.Split(s, ",")
	case "retention_days":
		c.RetentionDays, err = n()
	case "max_events":
		c.MaxEvents, err = n()
	case "max_alerts":
		c.MaxAlerts, err = n()
	case "max_body_mb":
		c.MaxBodyMB, err = n()
	case "dedup_window":
		c.DedupWindow, err = time.ParseDuration(s)
	case "agent_timeout":
		c.AgentTimeout, err = time.ParseDuration(s)
	default:
		// unknown keys are ignored so newer config files work with older servers
	}
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	return nil
}
