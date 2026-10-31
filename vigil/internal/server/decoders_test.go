package server

import (
	"testing"

	"github.com/vigil-siem/vigil/internal/common"
)

func dec(src, raw string) map[string]string {
	e := &common.Event{Category: "log", Source: src, Raw: raw}
	Decode(e)
	return e.Fields
}

func TestDecoders(t *testing.T) {
	cases := []struct {
		src, raw string
		want     map[string]string
	}{
		{"/var/log/auth.log", "Oct 29 22:10:01 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2",
			map[string]string{"log.service": "sshd", "event.action": "ssh_login", "event.outcome": "failure", "user.name": "admin", "source.ip": "203.0.113.9", "user.invalid": "true"}},
		{"/var/log/auth.log", "2026-10-29T22:10:01.123456+05:30 web01 sshd-session[99]: Accepted publickey for deploy from 10.0.0.5 port 2222 ssh2: ED25519 SHA256:x",
			map[string]string{"log.service": "sshd", "event.outcome": "success", "user.name": "deploy", "source.ip": "10.0.0.5", "auth.method": "publickey"}},
		{"/var/log/auth.log", "Oct 29 22:10:01 web01 sshd[1]: Invalid user oracle from 198.51.100.7 port 4444",
			map[string]string{"event.action": "ssh_invalid_user", "user.name": "oracle", "source.ip": "198.51.100.7"}},
		{"/var/log/auth.log", "Oct 29 22:11:00 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash",
			map[string]string{"log.service": "sudo", "event.action": "sudo_command", "user.name": "alice", "user.target": "root", "process.command_line": "/bin/bash"}},
		{"/var/log/auth.log", "Oct 29 22:11:00 web01 sudo:    bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/id",
			map[string]string{"event.action": "sudo_auth_failure", "user.name": "bob"}},
		{"/var/log/auth.log", "Oct 29 22:12:00 web01 useradd[77]: new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor, shell=/bin/bash",
			map[string]string{"log.service": "useradd", "event.action": "user_created", "user.target": "backdoor"}},
		{"/var/log/auth.log", "Oct 29 22:12:05 web01 usermod[78]: add 'backdoor' to group 'sudo'",
			map[string]string{"event.action": "group_member_added", "user.target": "backdoor", "group.name": "sudo"}},
		{"/var/log/auth.log", "Oct 29 22:12:05 web01 sshd[5]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.4  user=root",
			map[string]string{"event.action": "pam_auth_failure", "source.ip": "192.0.2.4", "user.name": "root"}},
		{"/var/log/nginx/access.log", `203.0.113.5 - - [29/Oct/2026:22:10:01 +0530] "GET /index.php?id=1%27%20or%201=1 HTTP/1.1" 404 153 "-" "sqlmap/1.7"`,
			map[string]string{"log.service": "nginx", "source.ip": "203.0.113.5", "url.path": "/index.php", "http.response.status_code": "404", "user_agent.original": "sqlmap/1.7"}},
		{"/var/log/audit/audit.log", `type=EXECVE msg=audit(1700000000.123:42): argc=3 a0="nc" a1="-e" a2="/bin/sh"`,
			map[string]string{"log.service": "auditd", "process.command_line": "nc -e /bin/sh", "auditd.type": "EXECVE"}},
		{"/var/log/app.json", `{"level":"error","msg":"login failed","user":{"name":"carol"},"status":401}`,
			map[string]string{"log.type": "json", "user.name": "carol", "status": "401", "message": "login failed"}},
	}
	for _, c := range cases {
		got := dec(c.src, c.raw)
		for k, v := range c.want {
			if got[k] != v {
				t.Errorf("%s\n  %s = %q, want %q (all: %v)", c.raw, k, got[k], v, got)
			}
		}
	}
}

func TestQuery(t *testing.T) {
	e := &common.Event{Hostname: "web01", Category: "log", Raw: "Failed password for root",
		Fields: map[string]string{"source.ip": "1.2.3.4", "user.name": "root", "http.response.status_code": "404"}}
	for q, want := range map[string]bool{
		"failed":                          true,
		`"failed password"`:               true,
		"source.ip:1.2.3.4":               true,
		"user.name:ro*":                   true,
		"-user.name:root":                 false,
		"http.response.status_code>=400":  true,
		"http.response.status_code<400":   false,
		"agent:web01 category:log failed": true,
		"agent:web02":                     false,
	} {
		if got := ParseQuery(q)(e); got != want {
			t.Errorf("%q = %v want %v", q, got, want)
		}
	}
}
