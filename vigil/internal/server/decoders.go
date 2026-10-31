package server

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vigil-siem/vigil/internal/common"
)

// Decoding happens on the server (like Wazuh's analysisd) so that raw lines
// from agents and from agentless syslog senders get the same treatment, and
// decoders can be improved without redeploying agents.

var (
	reSyslog = regexp.MustCompile(`^(?:<(\d+)>(?:1 )?)?(?:([A-Z][a-z]{2}\s+\d{1,2}\s\d\d:\d\d:\d\d)|(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?))\s+(\S+)\s+([^\s\[:]+)(?:\[(\d+)\])?:?\s*(.*)$`)

	reSSHFailed   = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(\S*) from (\S+) port (\d+)`)
	reSSHAccepted = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+)`)
	reSSHInvalid  = regexp.MustCompile(`^Invalid user (\S*) from (\S+)(?: port (\d+))?`)
	reSSHClosed   = regexp.MustCompile(`^(?:Connection closed|Disconnected) by (?:authenticating |invalid )?user (\S+) (\S+) port (\d+)`)
	rePAMFail     = regexp.MustCompile(`pam_unix\((\S+?):auth\): authentication failure;(?:.*?\brhost=(\S*))?(?:.*?\suser=(\S+))?`)
	reSudo        = regexp.MustCompile(`^\s*(\S+) : (?:(\d+) incorrect password attempts? ; )?(?:TTY=(\S+) ; )?PWD=(\S+) ; USER=(\S+) ; (?:COMMAND=(.*))?`)
	reSu          = regexp.MustCompile(`(FAILED SU|Successful su) for (\S+) by (\S+)`)
	reUserAdd     = regexp.MustCompile(`new user: name=([^,]+), UID=(\d+)`)
	reGroupAdd    = regexp.MustCompile(`(?:add '?([^' ]+)'? to (?:shadow )?group '?([^' ]+)'?|user (\S+) added by \S+ to group (\S+))`)
	reUserDel     = regexp.MustCompile(`delete user '?([^' ]+)'?`)
	reSession     = regexp.MustCompile(`session (opened|closed) for user (\S+?)(?:\(uid=\d+\))?(?: by (\S+?)(?:\(uid=\d+\))?)?$`)

	reAccess = regexp.MustCompile(`^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+)(?: (\S+))?" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?`)
	reKV     = regexp.MustCompile(`(\w+)=("([^"]*)"|'([^']*)'|\S+)`)
)

// Decode enriches e.Fields from e.Raw. It never overwrites existing fields.
func Decode(e *common.Event) {
	if e.Fields == nil {
		e.Fields = map[string]string{}
	}
	set := func(k, v string) {
		if v == "" {
			return
		}
		if _, ok := e.Fields[k]; !ok {
			e.Fields[k] = v
		}
	}
	raw := strings.TrimSpace(e.Raw)
	if raw == "" || e.Category != "log" {
		return
	}
	if _, ok := e.Fields["event.code"]; ok { // already structured (e.g. Windows)
		return
	}

	// JSON log lines: flatten into dotted keys.
	if strings.HasPrefix(raw, "{") {
		var m map[string]any
		if json.Unmarshal([]byte(raw), &m) == nil {
			flatten("", m, set)
			set("log.type", "json")
			if msg, ok := e.Fields["msg"]; ok {
				set("message", msg)
			}
			return
		}
	}

	// Web access logs (nginx / apache combined & common formats).
	if m := reAccess.FindStringSubmatch(raw); m != nil {
		set("log.type", "webserver")
		svc := "web"
		if strings.Contains(e.Source, "nginx") {
			svc = "nginx"
		} else if strings.Contains(e.Source, "apache") || strings.Contains(e.Source, "httpd") {
			svc = "apache"
		}
		set("log.service", svc)
		set("source.ip", m[1])
		if m[2] != "-" {
			set("user.name", m[2])
		}
		set("http.request.method", m[4])
		set("url.original", m[5])
		path, query, _ := strings.Cut(m[5], "?")
		set("url.path", path)
		set("url.query", query)
		set("http.version", m[6])
		set("http.response.status_code", m[7])
		if m[8] != "-" {
			set("http.response.body.bytes", m[8])
		}
		if m[9] != "" && m[9] != "-" {
			set("http.request.referrer", m[9])
		}
		set("user_agent.original", m[10])
		set("message", raw)
		return
	}

	// auditd records: type=EXECVE msg=audit(...): argc=2 a0="ls" a1="-la"
	if strings.HasPrefix(raw, "type=") {
		set("log.service", "auditd")
		args := map[int]string{}
		for _, kv := range reKV.FindAllStringSubmatch(raw, -1) {
			k, v := kv[1], kv[2]
			if kv[3] != "" || strings.HasPrefix(v, "\"") {
				v = kv[3]
			} else if kv[4] != "" {
				v = kv[4]
			}
			if len(k) > 1 && k[0] == 'a' {
				if n, err := strconv.Atoi(k[1:]); err == nil {
					args[n] = v
					continue
				}
			}
			set("auditd."+k, v)
		}
		if len(args) > 0 {
			parts := make([]string, len(args))
			for i := range parts {
				parts[i] = args[i]
			}
			set("process.command_line", strings.Join(parts, " "))
		}
		set("process.executable", e.Fields["auditd.exe"])
		set("user.id", e.Fields["auditd.uid"])
		set("message", raw)
		return
	}

	// Syslog header.
	msg := raw
	if m := reSyslog.FindStringSubmatch(raw); m != nil {
		host, prog, pid := m[4], m[5], m[6]
		msg = m[7]
		set("log.syslog.hostname", host)
		set("process.name", prog)
		set("process.pid", pid)
		svc := strings.ToLower(prog)
		if strings.HasPrefix(svc, "sshd") {
			svc = "sshd"
		}
		set("log.service", svc)
		if ts := parseSyslogTime(m[2], m[3]); !ts.IsZero() {
			set("log.timestamp", ts.Format(time.RFC3339))
		}
	}
	set("message", msg)
	svc := e.Fields["log.service"]

	switch {
	case svc == "sshd":
		decodeSSH(msg, set)
	case svc == "sudo":
		if m := reSudo.FindStringSubmatch(msg); m != nil {
			set("user.name", m[1])
			set("process.working_directory", m[4])
			set("user.target", m[5])
			set("process.command_line", strings.TrimSpace(m[6]))
			if m[2] != "" {
				set("event.action", "sudo_auth_failure")
				set("event.outcome", "failure")
			} else {
				set("event.action", "sudo_command")
				set("event.outcome", "success")
			}
		} else if m := rePAMFail.FindStringSubmatch(msg); m != nil {
			set("event.action", "sudo_auth_failure")
			set("event.outcome", "failure")
			set("user.name", m[3])
		}
	case svc == "su":
		if m := reSu.FindStringSubmatch(msg); m != nil {
			set("event.action", "su")
			set("user.target", m[2])
			set("user.name", m[3])
			if strings.HasPrefix(m[1], "FAILED") {
				set("event.outcome", "failure")
			} else {
				set("event.outcome", "success")
			}
		}
	}
	if m := reUserAdd.FindStringSubmatch(msg); m != nil {
		set("event.action", "user_created")
		set("user.target", m[1])
		set("user.id", m[2])
	}
	if m := reGroupAdd.FindStringSubmatch(msg); m != nil {
		set("event.action", "group_member_added")
		set("user.target", firstNonEmpty(m[1], m[3]))
		set("group.name", firstNonEmpty(m[2], m[4]))
	}
	if m := reUserDel.FindStringSubmatch(msg); m != nil {
		set("event.action", "user_deleted")
		set("user.target", m[1])
	}
	if m := reSession.FindStringSubmatch(msg); m != nil {
		set("event.action", "session_"+m[1])
		set("user.target", m[2])
		set("user.name", firstNonEmpty(m[3], m[2]))
	}
}

func decodeSSH(msg string, set func(string, string)) {
	switch {
	case reSSHFailed.MatchString(msg):
		m := reSSHFailed.FindStringSubmatch(msg)
		set("event.action", "ssh_login")
		set("event.outcome", "failure")
		set("auth.method", m[1])
		set("user.name", m[3])
		set("source.ip", m[4])
		set("source.port", m[5])
		if m[2] != "" {
			set("user.invalid", "true")
		}
	case reSSHAccepted.MatchString(msg):
		m := reSSHAccepted.FindStringSubmatch(msg)
		set("event.action", "ssh_login")
		set("event.outcome", "success")
		set("auth.method", m[1])
		set("user.name", m[2])
		set("source.ip", m[3])
		set("source.port", m[4])
	case reSSHInvalid.MatchString(msg):
		m := reSSHInvalid.FindStringSubmatch(msg)
		set("event.action", "ssh_invalid_user")
		set("event.outcome", "failure")
		set("user.name", m[1])
		set("source.ip", m[2])
		set("source.port", m[3])
	case reSSHClosed.MatchString(msg):
		m := reSSHClosed.FindStringSubmatch(msg)
		set("event.action", "ssh_disconnect")
		set("user.name", m[1])
		set("source.ip", m[2])
		set("source.port", m[3])
	case rePAMFail.MatchString(msg):
		m := rePAMFail.FindStringSubmatch(msg)
		set("event.action", "pam_auth_failure")
		set("event.outcome", "failure")
		set("source.ip", m[2])
		set("user.name", m[3])
	}
}

func parseSyslogTime(bsd, iso string) time.Time {
	if iso != "" {
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999-0700", "2006-01-02T15:04:05"} {
			if t, err := time.Parse(layout, iso); err == nil {
				return t
			}
		}
		return time.Time{}
	}
	if bsd != "" {
		t, err := time.ParseInLocation("Jan _2 15:04:05", strings.Join(strings.Fields(bsd), " "), time.Local)
		if err != nil {
			t, err = time.ParseInLocation("Jan 2 15:04:05", strings.Join(strings.Fields(bsd), " "), time.Local)
		}
		if err == nil {
			now := time.Now()
			t = t.AddDate(now.Year(), 0, 0)
			if t.After(now.Add(24 * time.Hour)) {
				t = t.AddDate(-1, 0, 0)
			}
			return t
		}
	}
	return time.Time{}
}

func flatten(prefix string, m map[string]any, set func(string, string)) {
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch x := v.(type) {
		case map[string]any:
			flatten(key, x, set)
		case string:
			set(key, x)
		case nil:
		default:
			b, _ := json.Marshal(x)
			s := string(b)
			if f, ok := x.(float64); ok {
				s = strconv.FormatFloat(f, 'f', -1, 64)
			}
			set(key, s)
		}
	}
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

// DescribeEvent renders a short human summary used in alert descriptions.
func DescribeEvent(e *common.Event) string {
	f := e.Fields
	switch {
	case f["event.action"] == "ssh_login":
		return fmt.Sprintf("SSH %s for %s from %s", f["event.outcome"], f["user.name"], f["source.ip"])
	case e.Category == "fim":
		return fmt.Sprintf("File %s: %s", f["event.action"], f["file.path"])
	case e.Category == "process":
		return fmt.Sprintf("Process %s (pid %s) by %s: %s", f["process.name"], f["process.pid"], f["user.name"], trunc(f["process.command_line"], 160))
	case f["url.original"] != "":
		return fmt.Sprintf("%s %s %s from %s", f["http.request.method"], trunc(f["url.original"], 120), f["http.response.status_code"], f["source.ip"])
	}
	if m := f["message"]; m != "" {
		return trunc(m, 200)
	}
	return trunc(e.Raw, 200)
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
