package agent

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync/atomic"
	"time"

	"github.com/vigil-siem/vigil/internal/common"
)

// Shipper batches events to the server and spools to disk while offline so
// nothing is lost during network outages or server restarts.
type Shipper struct {
	cfg      *Config
	client   *Client
	q        chan *common.Event
	spoolDir string
	sent     atomic.Int64
	dropped  atomic.Int64
	spooled  atomic.Int64
	online   atomic.Bool
}

func NewShipper(cfg *Config, c *Client) *Shipper {
	d := filepath.Join(cfg.StateDir, "spool")
	os.MkdirAll(d, 0o700)
	return &Shipper{cfg: cfg, client: c, q: make(chan *common.Event, cfg.QueueSize), spoolDir: d}
}

// Emit queues an event; it applies backpressure for up to 5s, then drops.
func (s *Shipper) Emit(e *common.Event) {
	if e.ID == "" {
		e.ID = common.NewID()
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	if e.Fields == nil {
		e.Fields = map[string]string{}
	}
	if _, ok := e.Fields["os.type"]; !ok {
		e.Fields["os.type"] = runtime.GOOS
	}
	select {
	case s.q <- e:
		return
	default:
	}
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	select {
	case s.q <- e:
	case <-t.C:
		s.dropped.Add(1)
	}
}

func (s *Shipper) QueueLen() int { return len(s.q) }

func (s *Shipper) Run(stop <-chan struct{}) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	var batch []*common.Event
	backoff := time.Second
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.send(batch); err != nil {
			s.online.Store(false)
			log.Printf("ship: %v (spooling %d events)", err, len(batch))
			s.spool(batch)
			time.Sleep(backoff)
			if backoff < time.Minute {
				backoff *= 2
			}
		} else {
			s.online.Store(true)
			backoff = time.Second
			s.drainSpool()
		}
		batch = nil
	}
	for {
		select {
		case <-stop:
			flush()
			return
		case e := <-s.q:
			batch = append(batch, e)
			if len(batch) >= s.cfg.BatchSize {
				flush()
			}
		case <-tick.C:
			flush()
			if len(batch) == 0 && s.online.Load() {
				s.drainSpool()
			}
		}
	}
}

func (s *Shipper) send(batch []*common.Event) error {
	evs := make([]common.Event, len(batch))
	for i, e := range batch {
		evs[i] = *e
	}
	if err := s.client.Post("/api/agent/events", common.EventBatch{Events: evs}, nil); err != nil {
		return err
	}
	s.sent.Add(int64(len(batch)))
	return nil
}

func (s *Shipper) spool(batch []*common.Event) {
	s.enforceSpoolLimit()
	f, err := os.OpenFile(filepath.Join(s.spoolDir, time.Now().Format("20060102T150405.000000000")+".jsonl"), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		s.dropped.Add(int64(len(batch)))
		return
	}
	w := bufio.NewWriter(f)
	for _, e := range batch {
		b, _ := json.Marshal(e)
		w.Write(b)
		w.WriteByte('\n')
	}
	w.Flush()
	f.Close()
	s.spooled.Add(int64(len(batch)))
}

func (s *Shipper) spoolFiles() []string {
	files, _ := filepath.Glob(filepath.Join(s.spoolDir, "*.jsonl"))
	sort.Strings(files)
	return files
}

func (s *Shipper) enforceSpoolLimit() {
	var total int64
	files := s.spoolFiles()
	sizes := make([]int64, len(files))
	for i, f := range files {
		if st, err := os.Stat(f); err == nil {
			sizes[i] = st.Size()
			total += st.Size()
		}
	}
	for i := 0; total > s.cfg.SpoolMaxMB<<20 && i < len(files); i++ {
		os.Remove(files[i])
		total -= sizes[i]
		s.dropped.Add(1)
		log.Printf("ship: spool over %d MB, dropped %s", s.cfg.SpoolMaxMB, filepath.Base(files[i]))
	}
}

// drainSpool resends up to 5 spooled batches per call, oldest first.
func (s *Shipper) drainSpool() {
	for i, f := range s.spoolFiles() {
		if i >= 5 {
			return
		}
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		var batch []*common.Event
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
		for sc.Scan() {
			var e common.Event
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				batch = append(batch, &e)
			}
		}
		fh.Close()
		if err := s.send(batch); err != nil {
			return
		}
		os.Remove(f)
		s.spooled.Add(-int64(len(batch)))
		log.Printf("ship: replayed %d spooled events", len(batch))
	}
}
