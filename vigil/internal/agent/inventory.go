package agent

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/vigil-siem/vigil/internal/common"
)

// CollectInventory gathers packages, processes, listening ports, users and
// OS details. Packages feed the server's vulnerability detector.
func CollectInventory(pm *ProcessMonitor) *common.Inventory {
	inv := &common.Inventory{Timestamp: time.Now(), Packages: packages(), Ports: listeningPorts(), OSRelease: osRelease(), Kernel: kernel()}
	if pm != nil {
		inv.Processes = pm.Snapshot()
	}
	inv.Users = localUsers()
	return inv
}

func run(name string, args ...string) []byte {
	if _, err := exec.LookPath(name); err != nil {
		return nil
	}
	b, _ := exec.Command(name, args...).Output()
	return b
}

func packages() []common.Package {
	var out []common.Package
	tabbed := func(b []byte, src string) {
		for _, l := range strings.Split(string(b), "\n") {
			n, v, ok := strings.Cut(strings.TrimSpace(l), "\t")
			if ok && n != "" {
				out = append(out, common.Package{Name: n, Version: v, Source: src})
			}
		}
	}
	switch runtime.GOOS {
	case "linux":
		tabbed(run("dpkg-query", "-W", "-f=${Package}\t${Version}\t${db:Status-Abbrev}\n"), "dpkg")
		// dpkg lines carry a third column (status); keep installed ("ii") only
		var cleaned []common.Package
		for _, p := range out {
			v, st, has := strings.Cut(p.Version, "\t")
			if has {
				if !strings.HasPrefix(st, "ii") {
					continue
				}
				p.Version = v
			}
			cleaned = append(cleaned, p)
		}
		out = cleaned
		b := run("rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n")
		tabbed(b, "rpm")
		if b := run("apk", "info", "-v"); b != nil {
			for _, l := range strings.Split(string(b), "\n") {
				// name-1.2.3-r0: version starts at the second-to-last '-'
				parts := strings.Split(strings.TrimSpace(l), "-")
				if len(parts) >= 3 {
					out = append(out, common.Package{Name: strings.Join(parts[:len(parts)-2], "-"), Version: strings.Join(parts[len(parts)-2:], "-"), Source: "apk"})
				}
			}
		}
	case "darwin":
		for _, l := range strings.Split(string(run("brew", "list", "--versions")), "\n") {
			f := strings.Fields(l)
			if len(f) >= 2 {
				out = append(out, common.Package{Name: f[0], Version: f[len(f)-1], Source: "brew"})
			}
		}
	case "windows":
		ps := `$k='HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object DisplayName | Select-Object DisplayName,DisplayVersion | ConvertTo-Csv -NoTypeInformation`
		b := run("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
		rows, _ := csv.NewReader(bytes.NewReader(b)).ReadAll()
		for i, r := range rows {
			if i > 0 && len(r) >= 2 {
				out = append(out, common.Package{Name: r[0], Version: r[1], Source: "windows"})
			}
		}
	}
	return out
}

func osRelease() string {
	if runtime.GOOS == "linux" {
		if f, err := os.Open("/etc/os-release"); err == nil {
			defer f.Close()
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				if v, ok := strings.CutPrefix(sc.Text(), "PRETTY_NAME="); ok {
					return strings.Trim(v, `"`)
				}
			}
		}
	}
	if runtime.GOOS == "darwin" {
		return "macOS " + strings.TrimSpace(string(run("sw_vers", "-productVersion")))
	}
	if runtime.GOOS == "windows" {
		return strings.TrimSpace(string(run("cmd", "/C", "ver")))
	}
	return runtime.GOOS
}

func kernel() string {
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		return strings.TrimSpace(string(b))
	}
	return strings.TrimSpace(string(run("uname", "-r")))
}

func localUsers() []string {
	var out []string
	if f, err := os.Open("/etc/passwd"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			p := strings.Split(sc.Text(), ":")
			if len(p) >= 7 && !strings.HasSuffix(p[6], "nologin") && !strings.HasSuffix(p[6], "false") {
				out = append(out, p[0]+" (uid "+p[2]+", "+p[6]+")")
			}
		}
	}
	return out
}
