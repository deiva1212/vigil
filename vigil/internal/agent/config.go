// Package agent implements the Vigil endpoint agent: log collection, file
// integrity monitoring, process and network monitoring, inventory,
// configuration assessment and active response.
package agent

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/vigil-siem/vigil/internal/yamlite"
)

const Version = "0.1.0"

type LogSource struct {
	Path    string // file path or glob
	Command string // long-running command whose stdout is collected
	Format  string // optional hint: syslog | json | access
	FromEnd bool   // start at end of file on first sight (default true)
}

type Config struct {
	Server             string
	EnrollmentKey      string
	ServerFingerprint  string
	CAFile             string
	InsecureSkipVerify bool
	Name               string
	Group              string
	StateDir           string

	HeartbeatInterval time.Duration
	FIMInterval       time.Duration
	InventoryInterval time.Duration
	SCAInterval       time.Duration
	ProcessInterval   time.Duration
	NetworkInterval   time.Duration

	Logs []LogSource

	FIMPaths    []string
	FIMIgnore   []string
	FIMMaxMB    int64
	FIMRealtime bool
	FIMMaxFiles int

	ProcessesEnabled bool
	NetworkEnabled   bool
	InventoryEnabled bool
	SCAEnabled       bool
	SCAPolicy        string

	AREnabled          bool
	ARDryRun           bool
	ARAllowed          []string
	QuarantineDir      string
	QuarantinePrefixes []string

	WinChannels []string

	BatchSize  int
	SpoolMaxMB int64
	QueueSize  int
}

func DefaultConfig() *Config {
	c := &Config{
		Group:             "default",
		HeartbeatInterval: 10 * time.Second,
		FIMInterval:       5 * time.Minute,
		InventoryInterval: time.Hour,
		SCAInterval:       12 * time.Hour,
		ProcessInterval:   2 * time.Second,
		NetworkInterval:   30 * time.Second,
		FIMMaxMB:          50,
		FIMRealtime:       true,
		FIMMaxFiles:       100000,
		ProcessesEnabled:  true,
		NetworkEnabled:    true,
		InventoryEnabled:  true,
		SCAEnabled:        true,
		AREnabled:         true,
		ARAllowed:         []string{"block_ip", "unblock_ip", "kill_process", "quarantine_file", "restore_file", "run_sca", "run_inventory", "run_fim", "restart_agent"},
		BatchSize:         500,
		SpoolMaxMB:        256,
		QueueSize:         20000,
	}
	switch runtime.GOOS {
	case "windows":
		c.StateDir = `C:\ProgramData\Vigil`
		c.FIMPaths = []string{`C:\Windows\System32\drivers\etc`, `C:\Windows\System32\Tasks`}
		c.WinChannels = []string{"Security", "System", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-PowerShell/Operational"}
		c.ProcessInterval = 10 * time.Second
		c.QuarantinePrefixes = []string{`C:\Users\`, `C:\Windows\Temp\`, `C:\ProgramData\`}
	case "darwin":
		c.StateDir = "/Library/Application Support/Vigil"
		c.FIMPaths = []string{"/etc", "/Library/LaunchDaemons", "/Library/LaunchAgents"}
		c.Logs = []LogSource{{Path: "/var/log/system.log"}}
		c.ProcessInterval = 5 * time.Second
		c.QuarantinePrefixes = []string{"/tmp/", "/private/tmp/", "/Users/"}
	default:
		c.StateDir = "/var/lib/vigil-agent"
		c.FIMPaths = []string{"/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/root/.ssh", "/var/spool/cron"}
		c.FIMIgnore = []string{"/etc/mtab", "/etc/adjtime", "/etc/ld.so.cache", "*.swp", "*~", "/etc/.pwd.lock"}
		c.Logs = []LogSource{
			{Path: "/var/log/auth.log"}, {Path: "/var/log/secure"}, {Path: "/var/log/syslog"},
			{Path: "/var/log/messages"}, {Path: "/var/log/nginx/access.log"},
			{Path: "/var/log/apache2/access.log"}, {Path: "/var/log/httpd/access_log"},
			{Path: "/var/log/audit/audit.log"},
		}
		c.QuarantinePrefixes = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/var/www/", "/srv/", "/opt/", "/root/"}
	}
	return c
}

// Load reads a YAML config file over the defaults.
func Load(path string) (*Config, error) {
	c := DefaultConfig()
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := c.Apply(string(b), false); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Apply merges YAML into the config. remote=true restricts it to the keys a
// server group config may set (never server address, keys or state dir).
func (c *Config) Apply(src string, remote bool) error {
	v, err := yamlite.Parse(src)
	if err != nil {
		return err
	}
	m, ok := v.(map[string]any)
	if !ok {
		if v == nil {
			return nil
		}
		return fmt.Errorf("config must be a YAML map")
	}
	local := map[string]bool{"server": true, "enrollment_key": true, "server_fingerprint": true, "ca_file": true,
		"insecure_skip_verify": true, "name": true, "group": true, "state_dir": true, "batch_size": true, "spool_max_mb": true}
	for k, val := range m {
		if remote && local[k] {
			continue
		}
		switch k {
		case "server":
			c.Server = strings.TrimRight(s(val), "/")
		case "enrollment_key":
			c.EnrollmentKey = s(val)
		case "server_fingerprint":
			c.ServerFingerprint = strings.ToLower(strings.ReplaceAll(s(val), ":", ""))
		case "ca_file":
			c.CAFile = s(val)
		case "insecure_skip_verify":
			c.InsecureSkipVerify = b(val)
		case "name":
			c.Name = s(val)
		case "group":
			c.Group = s(val)
		case "state_dir":
			c.StateDir = s(val)
		case "batch_size":
			c.BatchSize = atoi(val, c.BatchSize)
		case "spool_max_mb":
			c.SpoolMaxMB = int64(atoi(val, int(c.SpoolMaxMB)))
		case "intervals":
			im, _ := val.(map[string]any)
			for ik, iv := range im {
				d, err := time.ParseDuration(s(iv))
				if err != nil {
					return fmt.Errorf("intervals.%s: %w", ik, err)
				}
				switch ik {
				case "heartbeat":
					c.HeartbeatInterval = d
				case "fim":
					c.FIMInterval = d
				case "inventory":
					c.InventoryInterval = d
				case "sca":
					c.SCAInterval = d
				case "processes":
					c.ProcessInterval = d
				case "network":
					c.NetworkInterval = d
				}
			}
		case "logs":
			list, _ := val.([]any)
			var logs []LogSource
			for _, it := range list {
				switch x := it.(type) {
				case string:
					logs = append(logs, LogSource{Path: x, FromEnd: true})
				case map[string]any:
					ls := LogSource{Path: s(x["path"]), Command: s(x["command"]), Format: s(x["format"]), FromEnd: true}
					if fe, ok := x["from_beginning"]; ok && b(fe) {
						ls.FromEnd = false
					}
					logs = append(logs, ls)
				}
			}
			c.Logs = logs
		case "fim":
			fm, _ := val.(map[string]any)
			if p, ok := fm["paths"]; ok {
				c.FIMPaths = list(p)
			}
			if p, ok := fm["ignore"]; ok {
				c.FIMIgnore = list(p)
			}
			if p, ok := fm["max_file_mb"]; ok {
				c.FIMMaxMB = int64(atoi(p, int(c.FIMMaxMB)))
			}
			if p, ok := fm["max_files"]; ok {
				c.FIMMaxFiles = atoi(p, c.FIMMaxFiles)
			}
			if p, ok := fm["realtime"]; ok {
				c.FIMRealtime = b(p)
			}
		case "processes":
			c.ProcessesEnabled = enabled(val, c.ProcessesEnabled)
		case "network":
			c.NetworkEnabled = enabled(val, c.NetworkEnabled)
		case "inventory":
			c.InventoryEnabled = enabled(val, c.InventoryEnabled)
		case "sca":
			c.SCAEnabled = enabled(val, c.SCAEnabled)
			if mm, ok := val.(map[string]any); ok && mm["policy"] != nil {
				c.SCAPolicy = s(mm["policy"])
			}
		case "active_response":
			am, _ := val.(map[string]any)
			c.AREnabled = enabled(val, c.AREnabled)
			if v, ok := am["dry_run"]; ok {
				c.ARDryRun = b(v)
			}
			if v, ok := am["allowed"]; ok {
				c.ARAllowed = list(v)
			}
			if v, ok := am["quarantine_dir"]; ok {
				c.QuarantineDir = s(v)
			}
			if v, ok := am["quarantine_allowed_prefixes"]; ok {
				c.QuarantinePrefixes = list(v)
			}
		case "windows_eventlog":
			wm, _ := val.(map[string]any)
			if v, ok := wm["channels"]; ok {
				c.WinChannels = list(v)
			}
		}
	}
	return nil
}

func (c *Config) Validate() error {
	if c.Server == "" {
		return fmt.Errorf("server is required (e.g. https://vigil.example.com:8443)")
	}
	if !strings.HasPrefix(c.Server, "https://") && !strings.HasPrefix(c.Server, "http://") {
		return fmt.Errorf("server must start with https://")
	}
	if c.Name == "" {
		h, _ := os.Hostname()
		c.Name = sanitizeName(h)
	}
	if c.QuarantineDir == "" {
		c.QuarantineDir = c.StateDir + string(os.PathSeparator) + "quarantine"
	}
	return nil
}

func sanitizeName(h string) string {
	var bld strings.Builder
	for _, r := range h {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			bld.WriteRune(r)
		}
	}
	if bld.Len() == 0 {
		return "agent"
	}
	out := bld.String()
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

func s(v any) string {
	if v == nil {
		return ""
	}
	if x, ok := v.(string); ok {
		return x
	}
	return fmt.Sprint(v)
}

func b(v any) bool {
	x := strings.ToLower(s(v))
	return x == "true" || x == "yes" || x == "on" || x == "1"
}

func atoi(v any, def int) int {
	n, err := strconv.Atoi(s(v))
	if err != nil {
		return def
	}
	return n
}

func list(v any) []string {
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			out = append(out, s(e))
		}
		return out
	case string:
		return []string{x}
	}
	return nil
}

func enabled(v any, def bool) bool {
	switch x := v.(type) {
	case map[string]any:
		if e, ok := x["enabled"]; ok {
			return b(e)
		}
		return def
	case string:
		return b(x)
	}
	return def
}
