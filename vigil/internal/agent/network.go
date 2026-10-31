package agent

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/vigil-siem/vigil/internal/common"
)

// listeningPorts returns sockets in LISTEN state (TCP) or bound UDP sockets.
func listeningPorts() []common.Port {
	if runtime.GOOS == "linux" {
		inodes := socketInodes()
		var out []common.Port
		for _, t := range []struct{ file, proto string }{
			{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp6"}, {"/proc/net/udp", "udp"}, {"/proc/net/udp6", "udp6"},
		} {
			out = append(out, parseProcNet(t.file, t.proto, inodes)...)
		}
		return out
	}
	return netstatPorts()
}

func parseProcNet(file, proto string, inodes map[string]int) []common.Port {
	f, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []common.Port
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 10 {
			continue
		}
		state := fs[3]
		isTCP := strings.HasPrefix(proto, "tcp")
		if isTCP && state != "0A" { // 0A = LISTEN
			continue
		}
		if !isTCP && state != "07" { // 07 = unconnected/bound UDP
			continue
		}
		local := decodeAddr(fs[1])
		out = append(out, common.Port{Protocol: proto, Local: local, State: "LISTEN", PID: inodes[fs[9]]})
	}
	return out
}

func decodeAddr(s string) string {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return s
	}
	port, _ := strconv.ParseUint(p, 16, 16)
	b, err := hex.DecodeString(h)
	if err != nil {
		return s
	}
	// /proc stores addresses as little-endian 32-bit words
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return net.JoinHostPort(net.IP(b).String(), strconv.Itoa(int(port)))
}

// socketInodes maps socket inode -> owning PID.
func socketInodes() map[string]int {
	out := map[string]int{}
	procs, _ := filepath.Glob("/proc/[0-9]*/fd/*")
	for _, fd := range procs {
		t, err := os.Readlink(fd)
		if err != nil || !strings.HasPrefix(t, "socket:[") {
			continue
		}
		pid, _ := strconv.Atoi(strings.Split(fd, "/")[2])
		out[strings.TrimSuffix(strings.TrimPrefix(t, "socket:["), "]")] = pid
	}
	return out
}

func netstatPorts() []common.Port {
	args := []string{"-an"}
	if runtime.GOOS == "windows" {
		args = []string{"-ano"}
	}
	b, err := exec.Command("netstat", args...).Output()
	if err != nil {
		return nil
	}
	var out []common.Port
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 4 || !strings.Contains(strings.ToUpper(l), "LISTEN") {
			continue
		}
		p := common.Port{Protocol: strings.ToLower(f[0]), State: "LISTEN"}
		if runtime.GOOS == "windows" {
			p.Local = f[1]
			p.PID, _ = strconv.Atoi(f[len(f)-1])
		} else {
			p.Local = f[3]
		}
		out = append(out, p)
	}
	return out
}

// NetworkMonitor reports newly opened listening ports (possible backdoors).
type NetworkMonitor struct {
	cfg  *Config
	ship *Shipper
}

func (n *NetworkMonitor) Run(stop <-chan struct{}) {
	seen := map[string]bool{}
	first := true
	tick := time.NewTicker(n.cfg.NetworkInterval)
	defer tick.Stop()
	for {
		cur := map[string]bool{}
		for _, p := range listeningPorts() {
			k := p.Protocol + "|" + p.Local
			cur[k] = true
			if first || seen[k] {
				continue
			}
			host, port, _ := net.SplitHostPort(p.Local)
			fields := map[string]string{"event.action": "listen_port_opened", "network.transport": strings.TrimSuffix(p.Protocol, "6"),
				"destination.ip": host, "destination.port": port}
			if p.PID > 0 {
				fields["process.pid"] = strconv.Itoa(p.PID)
				if runtime.GOOS == "linux" {
					if pi := readProc(p.PID); pi != nil {
						fields["process.name"] = pi.Name
						fields["process.executable"] = pi.Exe
						fields["process.command_line"] = pi.Cmdline
						fields["user.name"] = pi.User
					}
				}
			}
			n.ship.Emit(&common.Event{Category: "network", Source: "network_monitor",
				Raw: fmt.Sprintf("new listening socket %s %s (pid %d %s)", p.Protocol, p.Local, p.PID, fields["process.name"]), Fields: fields})
		}
		for k := range seen {
			if !cur[k] && !first {
				proto, local, _ := strings.Cut(k, "|")
				host, port, _ := net.SplitHostPort(local)
				n.ship.Emit(&common.Event{Category: "network", Source: "network_monitor", Raw: "listening socket closed " + k,
					Fields: map[string]string{"event.action": "listen_port_closed", "network.transport": strings.TrimSuffix(proto, "6"), "destination.ip": host, "destination.port": port}})
			}
		}
		seen, first = cur, false
		select {
		case <-stop:
			return
		case <-tick.C:
		}
	}
}
