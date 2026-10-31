// Command vigil-agent is the Vigil endpoint agent.
//
//	vigil-agent -config /etc/vigil/agent.yml          run the agent
//	vigil-agent -config agent.yml check-config        validate config and exit
//	vigil-agent sca                                   run the local SCA policy and print results
//	vigil-agent version
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/vigil-siem/vigil/internal/agent"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("vigil-agent: ")
	cfgPath := flag.String("config", defaultConfigPath(), "agent config file")
	flag.Parse()
	cmd := flag.Arg(0)

	switch cmd {
	case "version":
		fmt.Println(agent.Version)
		return
	case "sca":
		cfg, err := agent.Load(optional(*cfgPath))
		if err != nil {
			log.Fatal(err)
		}
		pol, err := agent.LoadPolicy(cfg.SCAPolicy)
		if err != nil {
			log.Fatal(err)
		}
		rep := pol.Evaluate()
		pass, total := 0, 0
		for _, r := range rep.Results {
			fmt.Printf("%-15s %-9s %s\n", r.Result, r.CheckID, r.Title)
			if r.Result != "not_applicable" {
				total++
				if r.Result == "passed" {
					pass++
				}
			}
		}
		if total > 0 {
			fmt.Printf("\n%s: %d/%d passed (%d%%)\n", rep.Policy, pass, total, pass*100/total)
		}
		return
	}

	cfg, err := agent.Load(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}
	if cmd == "check-config" {
		fmt.Printf("config OK: server=%s name=%s group=%s logs=%d fim_paths=%d state=%s pinned=%v\n",
			cfg.Server, cfg.Name, cfg.Group, len(cfg.Logs), len(cfg.FIMPaths), cfg.StateDir, cfg.ServerFingerprint != "")
		return
	}
	if cmd != "" && cmd != "run" {
		log.Fatalf("unknown command %q (run, check-config, sca, version)", cmd)
	}
	a, err := agent.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if err := a.Run(); err != nil {
		log.Fatal(err)
	}
}

func defaultConfigPath() string {
	if p := os.Getenv("VIGIL_AGENT_CONFIG"); p != "" {
		return p
	}
	for _, p := range []string{"/etc/vigil/agent.yml", `C:\ProgramData\Vigil\agent.yml`, "agent.yml"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func optional(p string) string {
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}
