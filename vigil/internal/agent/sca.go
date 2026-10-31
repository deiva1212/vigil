package agent

import (
	"context"
	"embed"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/vigil-siem/vigil/internal/common"
	"github.com/vigil-siem/vigil/internal/yamlite"
)

//go:embed policies/*.yml
var builtinPolicies embed.FS

type scaCheck struct {
	ID, Title, Rationale, Remediation string
	Compliance                        []string
	File, FileMode, Max               string
	FileExists, FileMissing           string
	Command                           string
	Contains, NotContains             string
	ExpectEmpty                       bool
	Missing                           string
}

type scaPolicy struct {
	Name   string
	Checks []scaCheck
}

// LoadPolicy reads a policy file, or the built-in policy for this OS.
func LoadPolicy(path string) (*scaPolicy, error) {
	var src []byte
	var err error
	if path != "" {
		src, err = os.ReadFile(path)
	} else {
		src, err = builtinPolicies.ReadFile("policies/" + runtime.GOOS + ".yml")
	}
	if err != nil {
		return nil, err
	}
	v, err := yamlite.Parse(string(src))
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	p := &scaPolicy{Name: s(m["policy"])}
	items, _ := m["checks"].([]any)
	for _, it := range items {
		c, ok := it.(map[string]any)
		if !ok {
			continue
		}
		p.Checks = append(p.Checks, scaCheck{
			ID: s(c["id"]), Title: s(c["title"]), Rationale: s(c["rationale"]), Remediation: s(c["remediation"]),
			Compliance: list(c["compliance"]), File: s(c["file"]), FileMode: s(c["file_mode"]), Max: s(c["max"]),
			FileExists: s(c["file_exists"]), FileMissing: s(c["file_missing"]), Command: s(c["command"]),
			Contains: s(c["contains"]), NotContains: s(c["not_contains"]), ExpectEmpty: b(c["expect_empty"]),
			Missing: s(c["missing"]),
		})
	}
	return p, nil
}

// Evaluate runs every check.
func (p *scaPolicy) Evaluate() *common.SCAReport {
	rep := &common.SCAReport{Policy: p.Name, Timestamp: time.Now()}
	for _, c := range p.Checks {
		res, _ := c.run()
		rep.Results = append(rep.Results, common.SCAResult{CheckID: c.ID, Title: c.Title, Result: res,
			Rationale: c.Rationale, Remedy: c.Remediation, Compliance: c.Compliance})
	}
	return rep
}

func (c scaCheck) run() (string, error) {
	match := func(text string) (string, error) {
		if c.Contains != "" {
			re, err := regexp.Compile(c.Contains)
			if err != nil {
				return "not_applicable", err
			}
			if !re.MatchString(text) {
				return "failed", nil
			}
		}
		if c.NotContains != "" {
			re, err := regexp.Compile(c.NotContains)
			if err != nil {
				return "not_applicable", err
			}
			if re.MatchString(text) {
				return "failed", nil
			}
		}
		if c.ExpectEmpty && strings.TrimSpace(text) != "" {
			return "failed", nil
		}
		return "passed", nil
	}
	switch {
	case c.File != "":
		bs, err := os.ReadFile(c.File)
		if err != nil {
			if c.Missing == "fail" {
				return "failed", nil
			}
			return "not_applicable", nil
		}
		return match(string(bs))
	case c.FileMode != "":
		fi, err := os.Stat(c.FileMode)
		if err != nil {
			return "not_applicable", nil
		}
		max, err := strconv.ParseUint(c.Max, 8, 32)
		if err != nil {
			return "not_applicable", fmt.Errorf("bad max mode %q", c.Max)
		}
		if uint32(fi.Mode().Perm())&^uint32(max) != 0 {
			return "failed", nil
		}
		return "passed", nil
	case c.FileExists != "":
		if _, err := os.Stat(c.FileExists); err != nil {
			return "failed", nil
		}
		return "passed", nil
	case c.FileMissing != "":
		if _, err := os.Stat(c.FileMissing); err == nil {
			return "failed", nil
		}
		return "passed", nil
	case c.Command != "":
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.CommandContext(ctx, "cmd", "/C", c.Command)
		} else {
			cmd = exec.CommandContext(ctx, "/bin/sh", "-c", c.Command)
		}
		out, _ := cmd.CombinedOutput()
		return match(string(out))
	}
	return "not_applicable", nil
}
