package agent

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/vigil-siem/vigil/internal/common"
)

// Agent wires the collectors, shipper and responder together.
type Agent struct {
	cfg     *Config
	client  *Client
	ship    *Shipper
	logs    *LogCollector
	fim     *FIM
	procs   *ProcessMonitor
	resp    *Responder
	started time.Time
	remote  int

	invNow chan struct{}
	scaNow chan struct{}
}

func New(cfg *Config) (*Agent, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	a := &Agent{cfg: cfg, started: time.Now(), invNow: make(chan struct{}, 1), scaNow: make(chan struct{}, 1)}
	// apply the last group config received from the server
	var rc struct {
		Version int    `json:"version"`
		YAML    string `json:"yaml"`
	}
	if loadJSON(filepath.Join(cfg.StateDir, "remote_config.json"), &rc) && rc.YAML != "" {
		if err := cfg.Apply(rc.YAML, true); err != nil {
			log.Printf("config: cached group config invalid: %v", err)
		} else {
			a.remote = rc.Version
			log.Printf("config: applied group config v%d", rc.Version)
		}
	}
	var err error
	if a.client, err = NewClient(cfg); err != nil {
		return nil, err
	}
	a.ship = NewShipper(cfg, a.client)
	a.logs = NewLogCollector(cfg, a.ship)
	a.fim = NewFIM(cfg, a.ship)
	a.procs = NewProcessMonitor(cfg, a.ship)
	a.resp = NewResponder(cfg, a.client, a.ship, map[string]func(){
		"run_sca":       func() { kick(a.scaNow) },
		"run_inventory": func() { kick(a.invNow) },
		"run_fim":       a.fim.ScanNow,
	})
	return a, nil
}

func kick(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// Run blocks until SIGINT/SIGTERM.
func (a *Agent) Run() error {
	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	for !a.client.Enrolled() {
		err := a.client.Enroll()
		if err == nil {
			log.Printf("enrolled as %s (id %s)", a.cfg.Name, a.client.AgentID())
			break
		}
		log.Printf("%v; retrying in 15s", err)
		select {
		case <-sig:
			return nil
		case <-time.After(15 * time.Second):
		}
	}
	log.Printf("vigil-agent %s started: agent %s -> %s", Version, a.client.AgentID(), a.cfg.Server)

	var wg sync.WaitGroup
	start := func(name string, fn func(<-chan struct{})) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("%s crashed: %v", name, r)
				}
			}()
			fn(stop)
		}()
	}
	start("shipper", a.ship.Run)
	start("logs", a.logs.Run)
	start("fim", a.fim.Run)
	if a.cfg.ProcessesEnabled {
		start("processes", a.procs.Run)
	}
	if a.cfg.NetworkEnabled {
		start("network", (&NetworkMonitor{cfg: a.cfg, ship: a.ship}).Run)
	}
	if runtime.GOOS == "windows" {
		start("winlog", func(s <-chan struct{}) { RunWinlog(a.cfg, a.ship, s) })
	}
	if a.cfg.InventoryEnabled {
		start("inventory", a.inventoryLoop)
	}
	if a.cfg.SCAEnabled {
		start("sca", a.scaLoop)
	}
	start("heartbeat", a.heartbeatLoop)

	a.ship.Emit(&common.Event{Category: "agent", Source: "agent", Raw: "vigil agent started",
		Fields: map[string]string{"event.action": "agent_started", "agent.version": Version}})

	<-sig
	log.Printf("stopping")
	close(stop)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
	return nil
}

func localIP() string {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && ipn.IP.To4() != nil {
			return ipn.IP.String()
		}
	}
	return ""
}

func (a *Agent) heartbeatLoop(stop <-chan struct{}) {
	tick := time.NewTicker(a.cfg.HeartbeatInterval)
	defer tick.Stop()
	expire := time.NewTicker(30 * time.Second)
	defer expire.Stop()
	for {
		hb := common.HeartbeatRequest{Version: Version, QueueLen: a.ship.QueueLen(), Spooled: a.ship.spooled.Load(),
			Dropped: a.ship.dropped.Load(), Sent: a.ship.sent.Load(), UptimeSec: int64(time.Since(a.started).Seconds()),
			FIMFiles: a.fim.Count(), LogSources: a.logs.Sources(), IP: localIP()}
		var resp common.HeartbeatResponse
		err := a.client.Post("/api/agent/heartbeat", hb, &resp)
		switch {
		case errors.Is(err, ErrUnauthorized):
			log.Printf("heartbeat: credentials rejected; re-enrolling")
			if err := a.client.Enroll(); err != nil {
				log.Printf("re-enroll: %v", err)
			}
		case err != nil:
			log.Printf("heartbeat: %v", err)
		default:
			for _, c := range resp.Commands {
				go a.resp.Handle(c)
			}
			if resp.ConfigVersion != a.remote {
				a.syncConfig(resp.ConfigVersion)
			}
		}
		select {
		case <-stop:
			return
		case <-tick.C:
		case <-expire.C:
			a.resp.ExpireBlocks()
		}
	}
}

// syncConfig fetches the group config and restarts to apply it.
func (a *Agent) syncConfig(ver int) {
	var rc struct {
		Version int    `json:"version"`
		Group   string `json:"group"`
		YAML    string `json:"yaml"`
	}
	if err := a.client.Get("/api/agent/config", &rc); err != nil {
		log.Printf("config: fetch: %v", err)
		return
	}
	probe := DefaultConfig()
	if err := probe.Apply(rc.YAML, true); err != nil {
		log.Printf("config: group %s config rejected: %v", rc.Group, err)
		a.remote = rc.Version // don't retry a bad version in a loop
		return
	}
	saveJSON(filepath.Join(a.cfg.StateDir, "remote_config.json"), rc)
	log.Printf("config: group %s config v%d received; restarting to apply", rc.Group, rc.Version)
	a.remote = rc.Version
	time.Sleep(2 * time.Second) // let the shipper drain
	if err := restartSelf(); err != nil {
		log.Printf("config: restart failed: %v", err)
	}
}

func (a *Agent) inventoryLoop(stop <-chan struct{}) {
	first := time.NewTimer(15 * time.Second)
	tick := time.NewTicker(a.cfg.InventoryInterval)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-first.C:
		case <-tick.C:
		case <-a.invNow:
		}
		inv := CollectInventory(a.procs)
		var res map[string]int
		if err := a.client.Post("/api/agent/inventory", inv, &res); err != nil {
			log.Printf("inventory: %v", err)
			continue
		}
		log.Printf("inventory: %d packages, %d processes, %d ports -> %d vulnerabilities", len(inv.Packages), len(inv.Processes), len(inv.Ports), res["vulnerabilities"])
	}
}

func (a *Agent) scaLoop(stop <-chan struct{}) {
	first := time.NewTimer(20 * time.Second)
	tick := time.NewTicker(a.cfg.SCAInterval)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-first.C:
		case <-tick.C:
		case <-a.scaNow:
		}
		pol, err := LoadPolicy(a.cfg.SCAPolicy)
		if err != nil {
			log.Printf("sca: %v", err)
			continue
		}
		rep := pol.Evaluate()
		var res map[string]int
		if err := a.client.Post("/api/agent/sca", rep, &res); err != nil {
			log.Printf("sca: %v", err)
			continue
		}
		log.Printf("sca: %s score %s%%", rep.Policy, strconv.Itoa(res["score"]))
	}
}
