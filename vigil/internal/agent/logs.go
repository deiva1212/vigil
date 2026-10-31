package agent

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/vigil-siem/vigil/internal/common"
)

// saveJSON writes v atomically.
func saveJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadJSON(path string, v any) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return json.Unmarshal(b, v) == nil
}

type offsetState struct {
	Offset int64 `json:"offset"`
	Size   int64 `json:"size"`
}

// LogCollector tails files (with rotation and truncation handling) and
// streams the output of long-running commands such as journalctl -f.
type LogCollector struct {
	cfg     *Config
	ship    *Shipper
	mu      sync.Mutex
	offsets map[string]offsetState
	active  map[string]bool
	stateF  string
	sources int
}

func NewLogCollector(cfg *Config, ship *Shipper) *LogCollector {
	lc := &LogCollector{cfg: cfg, ship: ship, offsets: map[string]offsetState{}, active: map[string]bool{},
		stateF: filepath.Join(cfg.StateDir, "log_offsets.json")}
	loadJSON(lc.stateF, &lc.offsets)
	return lc
}

func (lc *LogCollector) Sources() int {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.sources
}

func (lc *LogCollector) Run(stop <-chan struct{}) {
	for _, src := range lc.cfg.Logs {
		if src.Command != "" {
			lc.mu.Lock()
			lc.sources++
			lc.mu.Unlock()
			go lc.runCommand(src, stop)
		}
	}
	save := time.NewTicker(5 * time.Second)
	discover := time.NewTicker(30 * time.Second)
	defer save.Stop()
	defer discover.Stop()
	lc.discover(stop)
	for {
		select {
		case <-stop:
			lc.save()
			return
		case <-save.C:
			lc.save()
		case <-discover.C:
			lc.discover(stop)
		}
	}
}

func (lc *LogCollector) save() {
	lc.mu.Lock()
	cp := make(map[string]offsetState, len(lc.offsets))
	for k, v := range lc.offsets {
		cp[k] = v
	}
	lc.mu.Unlock()
	saveJSON(lc.stateF, cp)
}

// discover expands globs and starts a tailer for each new file.
func (lc *LogCollector) discover(stop <-chan struct{}) {
	for _, src := range lc.cfg.Logs {
		if src.Path == "" {
			continue
		}
		matches, _ := filepath.Glob(src.Path)
		for _, p := range matches {
			st, err := os.Stat(p)
			if err != nil || st.IsDir() {
				continue
			}
			lc.mu.Lock()
			if lc.active[p] {
				lc.mu.Unlock()
				continue
			}
			lc.active[p] = true
			lc.sources++
			lc.mu.Unlock()
			log.Printf("logs: tailing %s", p)
			go lc.tail(p, src.FromEnd, stop)
		}
	}
}

func (lc *LogCollector) tail(path string, fromEnd bool, stop <-chan struct{}) {
	defer func() {
		lc.mu.Lock()
		delete(lc.active, path)
		lc.sources--
		lc.mu.Unlock()
	}()
	var f *os.File
	var fi os.FileInfo
	var rd *bufio.Reader
	var offset int64
	var partial []byte

	open := func(start int64) bool {
		var err error
		f, err = os.Open(path)
		if err != nil {
			return false
		}
		fi, _ = f.Stat()
		if start > fi.Size() {
			start = 0
		}
		f.Seek(start, io.SeekStart)
		offset = start
		rd = bufio.NewReaderSize(f, 64*1024)
		partial = nil
		return true
	}

	lc.mu.Lock()
	st, known := lc.offsets[path]
	lc.mu.Unlock()
	start := int64(0)
	if cur, err := os.Stat(path); err == nil {
		switch {
		case known && cur.Size() >= st.Offset:
			start = st.Offset // resume after restart
		case !known && fromEnd:
			start = cur.Size() // don't ingest history on first sight
		}
	}
	if !open(start) {
		return
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		// read everything available
		for {
			line, err := rd.ReadBytes('\n')
			if len(line) > 0 {
				if line[len(line)-1] != '\n' {
					partial = append(partial, line...) // incomplete line: wait
					break
				}
				offset += int64(len(partial) + len(line))
				full := append(partial, line...)
				partial = nil
				lc.emit(path, strings.TrimRight(string(full), "\r\n"))
			}
			if err != nil {
				break
			}
		}
		lc.mu.Lock()
		lc.offsets[path] = offsetState{Offset: offset, Size: fi.Size()}
		lc.mu.Unlock()

		select {
		case <-stop:
			return
		case <-tick.C:
		}

		cur, err := os.Stat(path)
		if err != nil {
			continue // rotated away; wait for a new file
		}
		if !os.SameFile(fi, cur) {
			// rotation: drain the old handle, then switch to the new file
			for {
				line, err := rd.ReadBytes('\n')
				if len(line) > 0 && line[len(line)-1] == '\n' {
					lc.emit(path, strings.TrimRight(string(append(partial, line...)), "\r\n"))
					partial = nil
				}
				if err != nil {
					break
				}
			}
			f.Close()
			log.Printf("logs: %s rotated", path)
			if !open(0) {
				return
			}
			continue
		}
		if cur.Size() < offset {
			log.Printf("logs: %s truncated", path)
			f.Seek(0, io.SeekStart)
			offset = 0
			rd.Reset(f)
			partial = nil
		}
		fi = cur
	}
}

func (lc *LogCollector) emit(source, line string) {
	if strings.TrimSpace(line) == "" {
		return
	}
	if len(line) > 32*1024 {
		line = line[:32*1024]
	}
	lc.ship.Emit(&common.Event{Category: "log", Source: source, Raw: line,
		Fields: map[string]string{"log.file.path": source}})
}

func (lc *LogCollector) runCommand(src LogSource, stop <-chan struct{}) {
	backoff := time.Second
	for {
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("cmd", "/C", src.Command)
		} else {
			cmd = exec.Command("/bin/sh", "-c", src.Command)
		}
		out, err := cmd.StdoutPipe()
		if err == nil {
			err = cmd.Start()
		}
		if err != nil {
			log.Printf("logs: command %q: %v", src.Command, err)
		} else {
			log.Printf("logs: streaming command %q", src.Command)
			done := make(chan struct{})
			go func() {
				select {
				case <-stop:
					cmd.Process.Kill()
				case <-done:
				}
			}()
			sc := bufio.NewScanner(out)
			sc.Buffer(make([]byte, 64*1024), 1024*1024)
			for sc.Scan() {
				lc.emit("cmd:"+src.Command, sc.Text())
			}
			cmd.Wait()
			close(done)
			backoff = time.Second
		}
		select {
		case <-stop:
			return
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}
