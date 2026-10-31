package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vigil-siem/vigil/internal/common"
)

type blockEntry struct {
	IP      string    `json:"ip"`
	Expires time.Time `json:"expires"` // zero = permanent
	Method  string    `json:"method"`
}

type quarantineMeta struct {
	Original string    `json:"original"`
	Stored   string    `json:"stored"`
	SHA256   string    `json:"sha256"`
	Mode     uint32    `json:"mode"`
	When     time.Time `json:"when"`
}

// Responder executes server commands. Every action is checked against the
// local allowlist so a compromised server cannot run arbitrary commands:
// there is deliberately no "run shell command" action.
type Responder struct {
	cfg       *Config
	client    *Client
	ship      *Shipper
	mu        sync.Mutex
	blocks    []blockEntry
	blockFile string
	triggers  map[string]func()
}

func NewResponder(cfg *Config, c *Client, ship *Shipper, triggers map[string]func()) *Responder {
	r := &Responder{cfg: cfg, client: c, ship: ship, blockFile: filepath.Join(cfg.StateDir, "blocks.json"), triggers: triggers}
	loadJSON(r.blockFile, &r.blocks)
	os.MkdirAll(cfg.QuarantineDir, 0o700)
	return r
}

func (r *Responder) allowed(action string) bool {
	if !r.cfg.AREnabled {
		return false
	}
	for _, a := range r.cfg.ARAllowed {
		if a == action {
			return true
		}
	}
	return false
}

// Handle executes one command and reports the result.
func (r *Responder) Handle(c common.Command) {
	status, out := "succeeded", ""
	var err error
	if !r.allowed(c.Action) {
		status, out = "failed", "action not allowed by agent configuration"
	} else if r.cfg.ARDryRun && c.Action != "run_sca" && c.Action != "run_inventory" && c.Action != "run_fim" {
		out = "dry-run: would execute " + c.Action + " " + fmt.Sprint(c.Args)
	} else {
		out, err = r.exec(c)
		if err != nil {
			status = "failed"
			out = strings.TrimSpace(out + " " + err.Error())
		}
	}
	log.Printf("response: %s %v -> %s %s", c.Action, c.Args, status, out)
	r.ship.Emit(&common.Event{Category: "response", Source: "active_response", Raw: fmt.Sprintf("active response %s %s: %s", c.Action, status, out),
		Fields: map[string]string{"event.action": "response_" + c.Action, "event.outcome": status, "response.command_id": c.ID,
			"source.ip": c.Args["ip"], "process.pid": c.Args["pid"], "file.path": c.Args["path"]}})
	if err := r.client.Post("/api/agent/command-result", common.CommandResult{CommandID: c.ID, Status: status, Output: out}, nil); err != nil {
		log.Printf("response: report result: %v", err)
	}
	if c.Action == "restart_agent" && status == "succeeded" {
		time.Sleep(time.Second)
		if err := restartSelf(); err != nil {
			log.Printf("restart: %v", err)
		}
	}
}

func (r *Responder) exec(c common.Command) (string, error) {
	switch c.Action {
	case "block_ip":
		var timeout time.Duration
		if t := c.Args["timeout"]; t != "" {
			timeout, _ = time.ParseDuration(t)
		}
		return r.block(c.Args["ip"], timeout)
	case "unblock_ip":
		return r.unblock(c.Args["ip"])
	case "kill_process":
		return killProcess(c.Args["pid"])
	case "quarantine_file":
		return r.quarantine(c.Args["path"])
	case "restore_file":
		return r.restore(c.Args["path"])
	case "run_sca", "run_inventory", "run_fim":
		if f := r.triggers[c.Action]; f != nil {
			go f()
			return "started", nil
		}
		return "", fmt.Errorf("%s is disabled on this agent", strings.TrimPrefix(c.Action, "run_"))
	case "restart_agent":
		return "restarting", nil
	}
	return "", fmt.Errorf("unknown action")
}

func cmdOut(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(b)), err
}

func have(name string) bool { _, err := exec.LookPath(name); return err == nil }

// ----------------------------------------------------------------- firewall

func (r *Responder) block(ipStr string, timeout time.Duration) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid ip %q", ipStr)
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return "", fmt.Errorf("refusing to block %s", ip)
	}
	ipStr = ip.String()
	r.mu.Lock()
	for i, b := range r.blocks {
		if b.IP == ipStr {
			if timeout > 0 {
				r.blocks[i].Expires = time.Now().Add(timeout)
			}
			r.mu.Unlock()
			r.save()
			return "already blocked; expiry extended", nil
		}
	}
	r.mu.Unlock()
	method, out, err := firewallBlock(ipStr, ip.To4() == nil)
	if err != nil {
		return out, err
	}
	e := blockEntry{IP: ipStr, Method: method}
	if timeout > 0 {
		e.Expires = time.Now().Add(timeout)
	}
	r.mu.Lock()
	r.blocks = append(r.blocks, e)
	r.mu.Unlock()
	r.save()
	msg := "blocked " + ipStr + " via " + method
	if timeout > 0 {
		msg += " for " + timeout.String()
	}
	return msg, nil
}

func firewallBlock(ip string, v6 bool) (string, string, error) {
	switch runtime.GOOS {
	case "linux":
		ipt := "iptables"
		if v6 {
			ipt = "ip6tables"
		}
		if have(ipt) {
			out, err := cmdOut(ipt, "-I", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "vigil")
			return ipt, out, err
		}
		if have("nft") {
			fam := "ip"
			if v6 {
				fam = "ip6"
			}
			cmdOut("nft", "add", "table", "inet", "vigil")
			cmdOut("nft", "add", "chain", "inet", "vigil", "input", "{ type filter hook input priority -10 ; }")
			out, err := cmdOut("nft", "add", "rule", "inet", "vigil", "input", fam, "saddr", ip, "drop")
			return "nftables", out, err
		}
		return "", "", fmt.Errorf("neither iptables nor nft is available")
	case "windows":
		out, err := cmdOut("netsh", "advfirewall", "firewall", "add", "rule", "name=vigil-block-"+ip, "dir=in", "action=block", "remoteip="+ip)
		return "netsh", out, err
	case "darwin":
		out, err := cmdOut("pfctl", "-t", "vigil_blocked", "-T", "add", ip)
		return "pf", out + " (requires a pf rule: block drop in quick from <vigil_blocked>)", err
	}
	return "", "", fmt.Errorf("blocking not supported on %s", runtime.GOOS)
}

func (r *Responder) unblock(ipStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid ip")
	}
	ipStr = ip.String()
	r.mu.Lock()
	var method string
	var keep []blockEntry
	for _, b := range r.blocks {
		if b.IP == ipStr {
			method = b.Method
		} else {
			keep = append(keep, b)
		}
	}
	r.blocks = keep
	r.mu.Unlock()
	r.save()
	var out string
	var err error
	switch method {
	case "iptables", "ip6tables":
		out, err = cmdOut(method, "-D", "INPUT", "-s", ipStr, "-j", "DROP", "-m", "comment", "--comment", "vigil")
	case "nftables":
		// delete by handle: find the rule that mentions the ip
		list, _ := cmdOut("nft", "-a", "list", "chain", "inet", "vigil", "input")
		for _, l := range strings.Split(list, "\n") {
			if strings.Contains(l, ipStr) && strings.Contains(l, "# handle ") {
				h := strings.TrimSpace(l[strings.LastIndex(l, "# handle ")+9:])
				out, err = cmdOut("nft", "delete", "rule", "inet", "vigil", "input", "handle", h)
			}
		}
	case "netsh":
		out, err = cmdOut("netsh", "advfirewall", "firewall", "delete", "rule", "name=vigil-block-"+ipStr)
	case "pf":
		out, err = cmdOut("pfctl", "-t", "vigil_blocked", "-T", "delete", ipStr)
	case "":
		return "not blocked by vigil", nil
	}
	if err != nil {
		return out, err
	}
	return "unblocked " + ipStr, nil
}

func (r *Responder) save() {
	r.mu.Lock()
	cp := append([]blockEntry(nil), r.blocks...)
	r.mu.Unlock()
	saveJSON(r.blockFile, cp)
}

// ExpireBlocks removes timed blocks; called periodically.
func (r *Responder) ExpireBlocks() {
	r.mu.Lock()
	var expired []string
	for _, b := range r.blocks {
		if !b.Expires.IsZero() && time.Now().After(b.Expires) {
			expired = append(expired, b.IP)
		}
	}
	r.mu.Unlock()
	for _, ip := range expired {
		out, err := r.unblock(ip)
		log.Printf("response: block on %s expired: %s %v", ip, out, err)
		r.ship.Emit(&common.Event{Category: "response", Source: "active_response", Raw: "block expired for " + ip,
			Fields: map[string]string{"event.action": "response_unblock_ip", "source.ip": ip, "event.outcome": "succeeded"}})
	}
}

// ------------------------------------------------------------- processes

func killProcess(pidStr string) (string, error) {
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 1 || pid == os.Getpid() || pid == os.Getppid() {
		return "", fmt.Errorf("refusing to kill pid %q", pidStr)
	}
	name := ""
	if runtime.GOOS == "linux" {
		if p := readProc(pid); p != nil {
			name = p.Name + " (" + p.Cmdline + ")"
		} else {
			return "", fmt.Errorf("process %d not found", pid)
		}
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return "", err
	}
	if err := proc.Kill(); err != nil {
		return "", err
	}
	return fmt.Sprintf("killed pid %d %s", pid, name), nil
}

// -------------------------------------------------------------- quarantine

func (r *Responder) pathAllowed(p string) bool {
	clean := filepath.Clean(p)
	for _, pre := range r.cfg.QuarantinePrefixes {
		if strings.HasPrefix(clean, filepath.Clean(pre)+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func (r *Responder) quarantine(p string) (string, error) {
	p = filepath.Clean(p)
	if !r.pathAllowed(p) {
		return "", fmt.Errorf("%s is outside quarantine_allowed_prefixes %v", p, r.cfg.QuarantinePrefixes)
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file")
	}
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	io.Copy(h, f)
	f.Close()
	sum := hex.EncodeToString(h.Sum(nil))
	stored := filepath.Join(r.cfg.QuarantineDir, time.Now().Format("20060102T150405")+"_"+sum[:12]+"_"+filepath.Base(p)+".quarantine")
	if err := moveFile(p, stored); err != nil {
		return "", err
	}
	os.Chmod(stored, 0)
	meta := quarantineMeta{Original: p, Stored: stored, SHA256: sum, Mode: uint32(fi.Mode().Perm()), When: time.Now()}
	saveJSON(stored+".json", meta)
	return fmt.Sprintf("quarantined %s (sha256 %s)", p, sum), nil
}

func (r *Responder) restore(p string) (string, error) {
	p = filepath.Clean(p)
	metas, _ := filepath.Glob(filepath.Join(r.cfg.QuarantineDir, "*.quarantine.json"))
	sort.Sort(sort.Reverse(sort.StringSlice(metas)))
	for _, mf := range metas {
		var m quarantineMeta
		if !loadJSON(mf, &m) || m.Original != p {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return "", fmt.Errorf("%s already exists; not overwriting", p)
		}
		if err := moveFile(m.Stored, p); err != nil {
			return "", err
		}
		os.Chmod(p, os.FileMode(m.Mode))
		os.Remove(mf)
		return "restored " + p, nil
	}
	return "", fmt.Errorf("no quarantined copy of %s", p)
}

func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src) // cross-device: copy then remove
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		in.Close()
		return err
	}
	_, err = io.Copy(out, in)
	in.Close()
	out.Close()
	if err != nil {
		os.Remove(dst)
		return err
	}
	return os.Remove(src)
}
