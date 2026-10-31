package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vigil-siem/vigil/internal/common"
)

type fileState struct {
	Size  int64  `json:"s"`
	Mode  string `json:"m"`
	MTime int64  `json:"t"`
	Hash  string `json:"h"`
	Owner string `json:"o"`
}

// FIM detects added, modified and deleted files with SHA-256 hashing,
// periodic full scans and (on Linux) realtime inotify triggers.
// For small text files under report_changes paths it also ships a line diff.
type FIM struct {
	cfg     *Config
	ship    *Shipper
	mu      sync.Mutex
	base    map[string]fileState
	path    string
	snapDir string
	trigger chan string
	scanNow chan struct{}
	ready   bool
}

var sensitiveNames = []string{"shadow", "gshadow", "shadow-", "gshadow-", "id_rsa", "id_ed25519", "id_ecdsa", ".key", ".pem", "credentials", "secret", "token", "passwd-"}

func NewFIM(cfg *Config, ship *Shipper) *FIM {
	f := &FIM{cfg: cfg, ship: ship, base: map[string]fileState{},
		path: filepath.Join(cfg.StateDir, "fim_baseline.json"), snapDir: filepath.Join(cfg.StateDir, "fim_snapshots"),
		trigger: make(chan string, 4096), scanNow: make(chan struct{}, 1)}
	f.ready = loadJSON(f.path, &f.base)
	os.MkdirAll(f.snapDir, 0o700)
	return f
}

func (f *FIM) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.base)
}

func (f *FIM) ScanNow() {
	select {
	case f.scanNow <- struct{}{}:
	default:
	}
}

func (f *FIM) Run(stop <-chan struct{}) {
	if len(f.cfg.FIMPaths) == 0 {
		return
	}
	f.fullScan()
	if f.cfg.FIMRealtime {
		go watchRealtime(f.cfg.FIMPaths, f.ignored, f.trigger, stop)
	}
	tick := time.NewTicker(f.cfg.FIMInterval)
	defer tick.Stop()
	pending := map[string]time.Time{}
	debounce := time.NewTicker(time.Second)
	defer debounce.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			f.fullScan()
		case <-f.scanNow:
			f.fullScan()
		case p := <-f.trigger:
			pending[p] = time.Now()
		case <-debounce.C:
			for p, t := range pending {
				if time.Since(t) >= 700*time.Millisecond {
					f.checkPath(p)
					delete(pending, p)
				}
			}
		}
	}
}

func (f *FIM) ignored(p string) bool {
	base := filepath.Base(p)
	for _, ig := range f.cfg.FIMIgnore {
		if ig == p || strings.HasPrefix(p, strings.TrimSuffix(ig, "/")+"/") {
			return true
		}
		if ok, _ := filepath.Match(ig, base); ok {
			return true
		}
	}
	return strings.HasPrefix(p, f.cfg.StateDir)
}

func (f *FIM) stat(p string, prev *fileState) (fileState, bool) {
	fi, err := os.Lstat(p)
	if err != nil || fi.IsDir() {
		return fileState{}, false
	}
	st := fileState{Size: fi.Size(), Mode: fmt.Sprintf("%04o", fi.Mode().Perm()), MTime: fi.ModTime().Unix(), Owner: fileOwner(fi)}
	if fi.Mode()&fs.ModeSymlink != 0 {
		t, _ := os.Readlink(p)
		st.Hash = "symlink:" + t
		return st, true
	}
	if !fi.Mode().IsRegular() {
		return fileState{}, false
	}
	// reuse the previous hash when size and mtime are unchanged
	if prev != nil && prev.Size == st.Size && prev.MTime == st.MTime && prev.Hash != "" {
		st.Hash = prev.Hash
		return st, true
	}
	if st.Size > f.cfg.FIMMaxMB<<20 {
		st.Hash = "too-large"
		return st, true
	}
	fh, err := os.Open(p)
	if err != nil {
		return st, true
	}
	h := sha256.New()
	io.Copy(h, fh)
	fh.Close()
	st.Hash = hex.EncodeToString(h.Sum(nil))
	return st, true
}

func (f *FIM) fullScan() {
	start := time.Now()
	f.mu.Lock()
	old := f.base
	f.mu.Unlock()
	cur := make(map[string]fileState, len(old))
	limitHit := false
	for _, root := range f.cfg.FIMPaths {
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if f.ignored(p) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if len(cur) >= f.cfg.FIMMaxFiles {
				limitHit = true
				return filepath.SkipAll
			}
			var prev *fileState
			if o, ok := old[p]; ok {
				prev = &o
			}
			if st, ok := f.stat(p, prev); ok {
				cur[p] = st
			}
			return nil
		})
	}
	if limitHit {
		log.Printf("fim: max_files (%d) reached; narrow fim.paths", f.cfg.FIMMaxFiles)
	}
	changes := 0
	if f.ready {
		for p, st := range cur {
			if o, ok := old[p]; !ok {
				f.report("added", p, nil, &st)
				changes++
			} else if o != st {
				f.report("modified", p, &o, &st)
				changes++
			}
		}
		for p, o := range old {
			if _, ok := cur[p]; !ok {
				o := o
				f.report("deleted", p, &o, nil)
				changes++
			}
		}
	} else {
		f.ship.Emit(&common.Event{Category: "agent", Source: "fim", Raw: fmt.Sprintf("FIM baseline created with %d files", len(cur)),
			Fields: map[string]string{"event.action": "fim_baseline", "fim.files": strconv.Itoa(len(cur))}})
		for p := range cur {
			f.snapshot(p)
		}
	}
	f.mu.Lock()
	f.base = cur
	f.ready = true
	f.mu.Unlock()
	saveJSON(f.path, cur)
	log.Printf("fim: scanned %d files in %s, %d changes", len(cur), time.Since(start).Round(time.Millisecond), changes)
}

// checkPath re-evaluates a single path after a realtime notification.
func (f *FIM) checkPath(p string) {
	if f.ignored(p) {
		return
	}
	f.mu.Lock()
	o, had := f.base[p]
	f.mu.Unlock()
	var prev *fileState
	if had {
		prev = &o
	}
	st, exists := f.stat(p, prev)
	if fi, err := os.Stat(p); err == nil && fi.IsDir() {
		return
	}
	f.mu.Lock()
	switch {
	case exists && !had:
		f.base[p] = st
		f.mu.Unlock()
		f.report("added", p, nil, &st)
	case exists && had && o != st:
		f.base[p] = st
		f.mu.Unlock()
		f.report("modified", p, &o, &st)
	case !exists && had:
		delete(f.base, p)
		f.mu.Unlock()
		f.report("deleted", p, &o, nil)
	default:
		f.mu.Unlock()
	}
}

func (f *FIM) report(action, p string, old, cur *fileState) {
	fields := map[string]string{"event.action": action, "file.path": p, "file.name": filepath.Base(p), "file.directory": filepath.Dir(p)}
	var changed []string
	if cur != nil {
		fields["file.size"] = strconv.FormatInt(cur.Size, 10)
		fields["file.mode"] = cur.Mode
		fields["file.owner"] = cur.Owner
		fields["file.mtime"] = time.Unix(cur.MTime, 0).UTC().Format(time.RFC3339)
		fields["file.hash.sha256"] = cur.Hash
	}
	if old != nil {
		fields["file.previous.hash.sha256"] = old.Hash
		fields["file.previous.size"] = strconv.FormatInt(old.Size, 10)
		fields["file.previous.mode"] = old.Mode
		fields["file.previous.owner"] = old.Owner
	}
	if old != nil && cur != nil {
		if old.Hash != cur.Hash {
			changed = append(changed, "content")
		}
		if old.Mode != cur.Mode {
			changed = append(changed, "permissions")
		}
		if old.Owner != cur.Owner {
			changed = append(changed, "owner")
		}
		if old.MTime != cur.MTime && len(changed) == 0 {
			changed = append(changed, "mtime")
		}
		fields["file.changed_attributes"] = strings.Join(changed, ",")
		if old.Hash != cur.Hash {
			if d := f.diff(p); d != "" {
				fields["file.diff"] = d
			}
		}
	}
	if action == "added" {
		f.snapshot(p)
	}
	if action == "deleted" {
		os.Remove(f.snapPath(p))
	}
	raw := fmt.Sprintf("File %s: %s", action, p)
	if len(changed) > 0 {
		raw += " (" + strings.Join(changed, ", ") + ")"
	}
	f.ship.Emit(&common.Event{Category: "fim", Source: "fim", Raw: raw, Fields: fields})
}

// ------------------------------------------------------------ change diffs

func isSensitive(p string) bool {
	lp := strings.ToLower(filepath.Base(p))
	for _, s := range sensitiveNames {
		if strings.Contains(lp, s) {
			return true
		}
	}
	return false
}

func (f *FIM) snapPath(p string) string {
	h := sha256.Sum256([]byte(p))
	return filepath.Join(f.snapDir, hex.EncodeToString(h[:12]))
}

// snapshot keeps a copy of small, non-sensitive text files for diffing.
func (f *FIM) snapshot(p string) {
	if isSensitive(p) {
		return
	}
	fi, err := os.Stat(p)
	if err != nil || fi.Size() > 64*1024 || !fi.Mode().IsRegular() {
		return
	}
	b, err := os.ReadFile(p)
	if err != nil || !isText(b) {
		return
	}
	os.WriteFile(f.snapPath(p), b, 0o600)
}

func isText(b []byte) bool {
	n := len(b)
	if n > 2048 {
		n = 2048
	}
	for _, c := range b[:n] {
		if c == 0 {
			return false
		}
	}
	return true
}

// diff returns removed (-) and added (+) lines, capped for readability.
func (f *FIM) diff(p string) string {
	if isSensitive(p) {
		return ""
	}
	oldB, err := os.ReadFile(f.snapPath(p))
	newB, err2 := os.ReadFile(p)
	if err2 != nil || len(newB) > 64*1024 || !isText(newB) {
		return ""
	}
	defer os.WriteFile(f.snapPath(p), newB, 0o600)
	if err != nil {
		return ""
	}
	oldL := strings.Split(string(oldB), "\n")
	newL := strings.Split(string(newB), "\n")
	oldSet, newSet := map[string]int{}, map[string]int{}
	for _, l := range oldL {
		oldSet[l]++
	}
	for _, l := range newL {
		newSet[l]++
	}
	var out []string
	for _, l := range oldL {
		if newSet[l] < oldSet[l] && l != "" {
			out = append(out, "- "+l)
			oldSet[l]--
		}
	}
	for _, l := range newL {
		if oldSet[l] < newSet[l] && l != "" {
			out = append(out, "+ "+l)
			newSet[l]--
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i][0] == '-' && out[j][0] == '+' })
	if len(out) > 30 {
		out = append(out[:30], fmt.Sprintf("… %d more lines", len(out)-30))
	}
	return strings.Join(out, "\n")
}
