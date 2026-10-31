package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vigil-siem/vigil/internal/common"
)

// CVEEntry is one record in the vulnerability feed.
//
// Affected when Introduced <= installed < Fixed (dpkg/rpm version ordering).
// Ecosystem limits matching to one package source (dpkg, rpm, apk, brew,
// windows); empty means any.
//
// The bundled feed is a small sample. In production, generate the feed from
// OSV.dev, the Debian/Ubuntu security trackers or Red Hat OVAL so that
// distro backports (fixed in a lower upstream version) are handled correctly.
type CVEEntry struct {
	ID         string   `json:"id"`
	Package    string   `json:"package"`
	Ecosystem  string   `json:"ecosystem,omitempty"`
	Introduced string   `json:"introduced,omitempty"`
	Fixed      string   `json:"fixed,omitempty"`
	Severity   string   `json:"severity"`
	CVSS       float64  `json:"cvss"`
	Summary    string   `json:"summary"`
	References []string `json:"references,omitempty"`
}

// VulnDB indexes CVE entries by package name.
type VulnDB struct {
	mu      sync.RWMutex
	byPkg   map[string][]CVEEntry
	count   int
	loaded  time.Time
	sources []string
}

func NewVulnDB() *VulnDB { return &VulnDB{byPkg: map[string][]CVEEntry{}} }

// LoadDir loads every *.json feed file in dir (array of CVEEntry).
func (db *VulnDB) LoadDir(dir string) error {
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	by := map[string][]CVEEntry{}
	n := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		var entries []CVEEntry
		if err := json.Unmarshal(b, &entries); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		for _, e := range entries {
			k := strings.ToLower(e.Package)
			by[k] = append(by[k], e)
			n++
		}
	}
	db.mu.Lock()
	db.byPkg, db.count, db.loaded, db.sources = by, n, time.Now(), files
	db.mu.Unlock()
	return nil
}

func (db *VulnDB) Count() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.count
}

// Scan matches an inventory against the feed.
func (db *VulnDB) Scan(inv *common.Inventory, hostname string) []VulnFinding {
	db.mu.RLock()
	defer db.mu.RUnlock()
	var out []VulnFinding
	now := time.Now()
	for _, p := range inv.Packages {
		for _, c := range db.byPkg[strings.ToLower(p.Name)] {
			if c.Ecosystem != "" && c.Ecosystem != p.Source {
				continue
			}
			if !Affected(p.Version, c.Introduced, c.Fixed) {
				continue
			}
			out = append(out, VulnFinding{
				CVE: c.ID, AgentID: inv.AgentID, Hostname: hostname, Package: p.Name,
				Version: p.Version, Fixed: c.Fixed, Severity: c.Severity, CVSS: c.CVSS,
				Summary: c.Summary, References: c.References, DetectedAt: now,
			})
		}
	}
	return out
}

// Affected reports introduced <= v < fixed.
//
// Debian/Ubuntu use "X+reallyY" when they roll a package back to upstream
// version Y while keeping a higher package version (e.g. xz-utils
// 5.6.1+really5.4.5 after the CVE-2024-3094 backdoor), so Y is what ships.
func Affected(v, introduced, fixed string) bool {
	if i := strings.Index(v, "+really"); i >= 0 {
		v = v[i+len("+really"):]
	}
	if introduced != "" && introduced != "0" && CompareVersions(v, introduced) < 0 {
		return false
	}
	if fixed != "" && CompareVersions(v, fixed) >= 0 {
		return false
	}
	return true
}

// CompareVersions implements Debian version ordering
// ([epoch:]upstream[-revision]); it also orders RPM and semver strings sanely.
func CompareVersions(a, b string) int {
	ea, ua, ra := splitVersion(a)
	eb, ub, rb := splitVersion(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}

func splitVersion(v string) (int, string, string) {
	epoch := 0
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch, _ = strconv.Atoi(v[:i])
		v = v[i+1:]
	}
	rev := ""
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		rev = v[i+1:]
		v = v[:i]
	}
	return epoch, v, rev
}

func order(c byte) int {
	switch {
	case c == 0, isDigit(c):
		return 0
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	case c == '~':
		return -1
	}
	return int(c) + 256
}

func at(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

// verrevcmp is a direct port of dpkg's lib/dpkg/version.c.
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		firstDiff := 0
		for (at(a, i) != 0 && !isDigit(at(a, i))) || (at(b, j) != 0 && !isDigit(at(b, j))) {
			ac, bc := order(at(a, i)), order(at(b, j))
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		for at(a, i) == '0' {
			i++
		}
		for at(b, j) == '0' {
			j++
		}
		for isDigit(at(a, i)) && isDigit(at(b, j)) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if isDigit(at(a, i)) {
			return 1
		}
		if isDigit(at(b, j)) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
