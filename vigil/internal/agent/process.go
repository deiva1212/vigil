package agent

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"fmt"
	"log"
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

type procInfo struct {
	common.Process
	Exe   string
	UID   string
	Start string // start time ticks: distinguishes PID reuse
}

// ---------------------------------------------------------- user lookup

var (
	usersMu   sync.Mutex
	usersByID map[string]string
	usersAt   time.Time
)

func userName(uid string) string {
	usersMu.Lock()
	defer usersMu.Unlock()
	if usersByID == nil || time.Since(usersAt) > 5*time.Minute {
		usersByID = map[string]string{}
		usersAt = time.Now()
		if f, err := os.Open("/etc/passwd"); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				p := strings.Split(sc.Text(), ":")
				if len(p) > 2 {
					usersByID[p[2]] = p[0]
				}
			}
			f.Close()
		}
	}
	if n, ok := usersByID[uid]; ok {
		return n
	}
	return uid
}

// ---------------------------------------------------------- snapshots

func snapshotProcesses() map[int]*procInfo {
	switch runtime.GOOS {
	case "linux":
		return procSnapshot()
	case "windows":
		return windowsSnapshot()
	default:
		return psSnapshot()
	}
}

func procSnapshot() map[int]*procInfo {
	out := map[int]*procInfo{}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if p := readProc(pid); p != nil {
			out[pid] = p
		}
	}
	return out
}

func readProc(pid int) *procInfo {
	dir := "/proc/" + strconv.Itoa(pid)
	stat, err := os.ReadFile(dir + "/stat")
	if err != nil {
		return nil
	}
	// comm is in parentheses and may contain spaces: split on the last ')'
	s := string(stat)
	lp, rp := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if lp < 0 || rp < lp {
		return nil
	}
	comm := s[lp+1 : rp]
	rest := strings.Fields(s[rp+1:])
	if len(rest) < 20 {
		return nil
	}
	ppid, _ := strconv.Atoi(rest[1])
	p := &procInfo{Process: common.Process{PID: pid, PPID: ppid, Name: comm}, Start: rest[19]}
	if cl, err := os.ReadFile(dir + "/cmdline"); err == nil {
		p.Cmdline = strings.TrimSpace(string(bytes.ReplaceAll(cl, []byte{0}, []byte{' '})))
	}
	p.Exe, _ = os.Readlink(dir + "/exe")
	p.Exe = strings.TrimSuffix(p.Exe, " (deleted)")
	if st, err := os.ReadFile(dir + "/status"); err == nil {
		for _, l := range strings.Split(string(st), "\n") {
			if strings.HasPrefix(l, "Uid:") {
				f := strings.Fields(l)
				if len(f) > 1 {
					p.UID = f[1]
					p.User = userName(f[1])
				}
				break
			}
		}
	}
	return p
}

func psSnapshot() map[int]*procInfo {
	out := map[int]*procInfo{}
	b, err := exec.Command("ps", "-axww", "-o", "pid=,ppid=,user=,args=").Output()
	if err != nil {
		return out
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		pid, _ := strconv.Atoi(f[0])
		ppid, _ := strconv.Atoi(f[1])
		args := strings.Join(f[3:], " ")
		exe := f[3]
		out[pid] = &procInfo{Process: common.Process{PID: pid, PPID: ppid, User: f[2], Name: filepath.Base(exe), Cmdline: args}, Exe: exe}
	}
	return out
}

func windowsSnapshot() map[int]*procInfo {
	out := map[int]*procInfo{}
	ps := `Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Csv -NoTypeInformation`
	b, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Output()
	if err != nil {
		return out
	}
	rows, err := csv.NewReader(bytes.NewReader(b)).ReadAll()
	if err != nil {
		return out
	}
	for i, r := range rows {
		if i == 0 || len(r) < 5 {
			continue
		}
		pid, _ := strconv.Atoi(r[0])
		ppid, _ := strconv.Atoi(r[1])
		out[pid] = &procInfo{Process: common.Process{PID: pid, PPID: ppid, Name: r[2], Cmdline: r[4]}, Exe: r[3]}
	}
	return out
}

// ------------------------------------------------------- process monitor

// ProcessMonitor emits a process_creation event for every new process.
// Polling misses processes shorter than the interval; for full coverage
// enable auditd EXECVE logging (Linux), Sysmon (Windows) or an eBPF probe.
type ProcessMonitor struct {
	cfg  *Config
	ship *Shipper
	seen map[string]bool
	last map[int]*procInfo
	mu   sync.Mutex
}

func NewProcessMonitor(cfg *Config, ship *Shipper) *ProcessMonitor {
	return &ProcessMonitor{cfg: cfg, ship: ship, seen: map[string]bool{}}
}

func procKey(p *procInfo) string { return strconv.Itoa(p.PID) + ":" + p.Start + ":" + p.Cmdline }

// Snapshot returns the last process list (for inventory).
func (m *ProcessMonitor) Snapshot() []common.Process {
	m.mu.Lock()
	defer m.mu.Unlock()
	snap := m.last
	if snap == nil {
		snap = snapshotProcesses()
	}
	out := make([]common.Process, 0, len(snap))
	for _, p := range snap {
		out = append(out, p.Process)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

func (m *ProcessMonitor) Run(stop <-chan struct{}) {
	self := os.Getpid()
	first := true
	tick := time.NewTicker(m.cfg.ProcessInterval)
	defer tick.Stop()
	for {
		snap := snapshotProcesses()
		cur := map[string]bool{}
		emitted := 0
		for _, p := range snap {
			k := procKey(p)
			cur[k] = true
			if first || m.seen[k] || p.PID == self || p.PPID == self {
				continue
			}
			if runtime.GOOS == "linux" && p.Cmdline == "" && (p.PPID == 2 || p.PID == 2) {
				continue // kernel thread
			}
			if emitted >= 500 {
				continue
			}
			emitted++
			m.emit(p, snap[p.PPID])
		}
		m.mu.Lock()
		m.seen, m.last = cur, snap
		m.mu.Unlock()
		if first {
			log.Printf("processes: baseline %d processes", len(snap))
			first = false
		}
		select {
		case <-stop:
			return
		case <-tick.C:
		}
	}
}

func (m *ProcessMonitor) emit(p, parent *procInfo) {
	f := map[string]string{
		"event.action":         "process_started",
		"process.pid":          strconv.Itoa(p.PID),
		"process.ppid":         strconv.Itoa(p.PPID),
		"process.name":         p.Name,
		"process.executable":   p.Exe,
		"process.command_line": p.Cmdline,
		"user.name":            p.User,
		"user.id":              p.UID,
	}
	if parent != nil {
		f["process.parent.name"] = parent.Name
		f["process.parent.executable"] = parent.Exe
		f["process.parent.command_line"] = parent.Cmdline
	}
	for k, v := range f {
		if v == "" {
			delete(f, k)
		}
	}
	m.ship.Emit(&common.Event{Category: "process", Source: "process_monitor",
		Raw: fmt.Sprintf("process started pid=%d user=%s cmd=%s", p.PID, p.User, p.Cmdline), Fields: f})
}
