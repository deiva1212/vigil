package server

import (
	"bufio"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/vigil-siem/vigil/internal/common"
)

// SyslogReceiver accepts agentless logs (firewalls, routers, appliances) on
// UDP and TCP. Each sender IP is registered as an agentless device.
type SyslogReceiver struct {
	engine *Engine
	store  *Store
	mu     sync.Mutex
	buf    []*common.Event
	seen   map[string]time.Time
}

func StartSyslog(addr string, engine *Engine, store *Store) {
	if addr == "" {
		return
	}
	r := &SyslogReceiver{engine: engine, store: store, seen: map[string]time.Time{}}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Printf("syslog: udp %s: %v", addr, err)
	} else {
		go r.serveUDP(pc)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("syslog: tcp %s: %v", addr, err)
	} else {
		go r.serveTCP(ln)
	}
	go r.flushLoop()
	log.Printf("syslog: listening on %s (udp+tcp)", addr)
}

func (r *SyslogReceiver) serveUDP(pc net.PacketConn) {
	b := make([]byte, 64*1024)
	for {
		n, addr, err := pc.ReadFrom(b)
		if err != nil {
			log.Printf("syslog: udp: %v", err)
			return
		}
		ip, _, _ := net.SplitHostPort(addr.String())
		for _, line := range strings.Split(string(b[:n]), "\n") {
			r.add(ip, line)
		}
	}
}

func (r *SyslogReceiver) serveTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("syslog: tcp: %v", err)
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			sc := bufio.NewScanner(c)
			sc.Buffer(make([]byte, 64*1024), 1024*1024)
			for sc.Scan() {
				r.add(ip, sc.Text())
			}
		}(c)
	}
}

func (r *SyslogReceiver) add(ip, line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	id := "syslog:" + ip
	e := &common.Event{ID: common.NewID(), AgentID: id, Hostname: ip, Timestamp: time.Now(),
		Category: "log", Source: "syslog", Raw: line, Fields: map[string]string{"observer.ip": ip}}
	r.mu.Lock()
	r.buf = append(r.buf, e)
	register := time.Since(r.seen[id]) > 30*time.Second
	if register {
		r.seen[id] = time.Now()
	}
	r.mu.Unlock()
	if register {
		if a := r.store.Agent(id); a == nil {
			r.store.PutAgent(&common.AgentInfo{ID: id, Name: ip, Hostname: ip, OS: "syslog device",
				IP: ip, Group: "agentless", EnrolledAt: time.Now(), LastSeen: time.Now(), Status: "active", Version: "syslog"})
		} else {
			r.store.UpdateAgent(id, func(a *common.AgentInfo) { a.LastSeen = time.Now(); a.Status = "active" })
		}
	}
}

func (r *SyslogReceiver) flushLoop() {
	t := time.NewTicker(time.Second)
	for range t.C {
		r.mu.Lock()
		batch := r.buf
		r.buf = nil
		r.mu.Unlock()
		if len(batch) == 0 {
			continue
		}
		for _, e := range batch {
			Decode(e)
			if h := e.Fields["log.syslog.hostname"]; h != "" {
				e.Hostname = h
			}
		}
		r.engine.Ingest(batch)
	}
}
