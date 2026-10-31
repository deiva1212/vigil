package server

import (
	"sort"
	"strings"

	"github.com/vigil-siem/vigil/internal/common"
)

// Tactics in ATT&CK kill-chain order (Enterprise matrix).
var Tactics = []string{
	"reconnaissance", "resource-development", "initial-access", "execution",
	"persistence", "privilege-escalation", "defense-evasion", "credential-access",
	"discovery", "lateral-movement", "collection", "command-and-control",
	"exfiltration", "impact",
}

// TechniqueNames covers the techniques referenced by the bundled rules.
var TechniqueNames = map[string]string{
	"T1046": "Network Service Discovery", "T1053.003": "Scheduled Task: Cron",
	"T1036": "Masquerading", "T1059.001": "PowerShell", "T1059.004": "Unix Shell",
	"T1070.001": "Clear Windows Event Logs", "T1070.003": "Clear Command History",
	"T1071": "Application Layer Protocol", "T1078": "Valid Accounts",
	"T1078.003": "Local Accounts", "T1087": "Account Discovery",
	"T1098": "Account Manipulation", "T1098.004": "SSH Authorized Keys",
	"T1105": "Ingress Tool Transfer", "T1110": "Brute Force",
	"T1110.001": "Password Guessing", "T1110.003": "Password Spraying",
	"T1136.001": "Create Local Account", "T1190": "Exploit Public-Facing Application",
	"T1496": "Resource Hijacking", "T1505.003": "Web Shell",
	"T1531": "Account Access Removal", "T1543.002": "Systemd Service",
	"T1547.006": "Kernel Modules and Extensions", "T1548.003": "Sudo and Sudo Caching",
	"T1562": "Impair Defenses", "T1571": "Non-Standard Port", "T1562.001": "Disable or Modify Tools", "T1565.001": "Stored Data Manipulation",
	"T1595.002": "Vulnerability Scanning", "T1595.003": "Wordlist Scanning",
}

// Frameworks supported in the compliance view.
var Frameworks = []string{"PCI-DSS", "HIPAA", "NIST-800-53", "GDPR", "ISO-27001", "CIS"}

// tacticControls maps ATT&CK tactics to the controls an alert evidences.
// It is an opinionated starting point, not legal advice: review with your
// auditor and extend per rule with the `compliance:` field.
var tacticControls = map[string][]string{
	"credential-access":    {"PCI-DSS 8.3.4", "PCI-DSS 10.2.1.4", "NIST-800-53 AC-7", "NIST-800-53 IA-2", "HIPAA 164.312(d)", "ISO-27001 A.8.5", "GDPR Art.32"},
	"initial-access":       {"PCI-DSS 10.2.1", "NIST-800-53 AC-17", "ISO-27001 A.8.20", "HIPAA 164.312(b)"},
	"privilege-escalation": {"PCI-DSS 10.2.1.2", "PCI-DSS 7.2.1", "NIST-800-53 AC-6", "HIPAA 164.308(a)(4)", "ISO-27001 A.8.2"},
	"persistence":          {"PCI-DSS 11.5.2", "NIST-800-53 SI-7", "NIST-800-53 CM-3", "ISO-27001 A.8.9"},
	"defense-evasion":      {"PCI-DSS 10.3.2", "NIST-800-53 AU-9", "HIPAA 164.312(b)", "ISO-27001 A.8.15"},
	"execution":            {"PCI-DSS 5.2.1", "NIST-800-53 SI-3", "NIST-800-53 SI-4", "ISO-27001 A.8.7"},
	"impact":               {"PCI-DSS 12.10.1", "NIST-800-53 IR-4", "GDPR Art.33", "HIPAA 164.308(a)(6)"},
	"discovery":            {"PCI-DSS 11.4.1", "NIST-800-53 SI-4"},
	"reconnaissance":       {"PCI-DSS 11.4.1", "NIST-800-53 SI-4", "NIST-800-53 RA-5"},
	"command-and-control":  {"PCI-DSS 1.4.1", "NIST-800-53 SC-7", "NIST-800-53 SI-4"},
	"lateral-movement":     {"NIST-800-53 AC-4", "PCI-DSS 1.3.1"},
	"exfiltration":         {"NIST-800-53 SC-7", "GDPR Art.32", "GDPR Art.33", "HIPAA 164.312(e)(1)"},
	"collection":           {"GDPR Art.32", "HIPAA 164.312(a)(1)"},
}

var kindControls = map[string][]string{
	"vulnerability": {"PCI-DSS 6.3.3", "PCI-DSS 11.3.1", "NIST-800-53 RA-5", "NIST-800-53 SI-2", "HIPAA 164.308(a)(1)(ii)(A)", "ISO-27001 A.8.8"},
	"sca":           {"PCI-DSS 2.2.1", "NIST-800-53 CM-6", "ISO-27001 A.8.9", "CIS"},
}

// MapCompliance returns the control IDs an alert evidences.
func MapCompliance(tags []string, kind string, explicit []string) []string {
	set := map[string]bool{}
	for _, c := range explicit {
		set[c] = true
	}
	for _, t := range tags {
		t = strings.ToLower(t)
		if strings.HasPrefix(t, "attack.") {
			for _, c := range tacticControls[strings.TrimPrefix(t, "attack.")] {
				set[c] = true
			}
		}
	}
	for _, c := range kindControls[kind] {
		set[c] = true
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// ComplianceReport summarises alerts per framework and control.
type ComplianceReport struct {
	Framework string          `json:"framework"`
	Controls  []ControlStatus `json:"controls"`
	Alerts    int             `json:"alerts"`
}

type ControlStatus struct {
	Control string         `json:"control"`
	Alerts  int            `json:"alerts"`
	Levels  map[string]int `json:"levels"`
	Rules   []string       `json:"rules"`
}

func BuildCompliance(alerts []*common.Alert) []ComplianceReport {
	per := map[string]map[string]*ControlStatus{}
	totals := map[string]int{}
	for _, a := range alerts {
		seenFw := map[string]bool{}
		for _, c := range a.Compliance {
			fw, ctl, ok := strings.Cut(c, " ")
			if !ok {
				fw, ctl = c, c
			}
			if per[fw] == nil {
				per[fw] = map[string]*ControlStatus{}
			}
			cs := per[fw][ctl]
			if cs == nil {
				cs = &ControlStatus{Control: ctl, Levels: map[string]int{}}
				per[fw][ctl] = cs
			}
			cs.Alerts++
			cs.Levels[a.Level]++
			if len(cs.Rules) < 8 && !containsStr(cs.Rules, a.RuleTitle) {
				cs.Rules = append(cs.Rules, a.RuleTitle)
			}
			if !seenFw[fw] {
				totals[fw]++
				seenFw[fw] = true
			}
		}
	}
	var out []ComplianceReport
	for _, fw := range Frameworks {
		r := ComplianceReport{Framework: fw, Alerts: totals[fw], Controls: []ControlStatus{}}
		for _, cs := range per[fw] {
			r.Controls = append(r.Controls, *cs)
		}
		sort.Slice(r.Controls, func(i, j int) bool { return r.Controls[i].Control < r.Controls[j].Control })
		out = append(out, r)
	}
	return out
}

// MitreCell is one technique under one tactic in the ATT&CK matrix view.
type MitreCell struct {
	Technique string `json:"technique"`
	Name      string `json:"name"`
	Count     int    `json:"count"`
	MaxLevel  string `json:"max_level"`
}

type MitreColumn struct {
	Tactic     string      `json:"tactic"`
	Techniques []MitreCell `json:"techniques"`
	Count      int         `json:"count"`
}

var levelRank = map[string]int{"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

func BuildMitre(alerts []*common.Alert) []MitreColumn {
	cells := map[string]map[string]*MitreCell{}
	for _, a := range alerts {
		var tactics []string
		for _, t := range a.Tags {
			t = strings.ToLower(t)
			if strings.HasPrefix(t, "attack.") && !isTechniqueTag(t) {
				tactics = append(tactics, strings.TrimPrefix(t, "attack."))
			}
		}
		for _, tac := range tactics {
			if cells[tac] == nil {
				cells[tac] = map[string]*MitreCell{}
			}
			for _, tech := range a.MITRE {
				if !strings.HasPrefix(tech, "T") {
					continue
				}
				c := cells[tac][tech]
				if c == nil {
					c = &MitreCell{Technique: tech, Name: TechniqueNames[tech]}
					if c.Name == "" {
						c.Name = tech
					}
					cells[tac][tech] = c
				}
				c.Count += max(a.Count, 1)
				if levelRank[a.Level] >= levelRank[c.MaxLevel] {
					c.MaxLevel = a.Level
				}
			}
		}
	}
	var out []MitreColumn
	for _, tac := range Tactics {
		col := MitreColumn{Tactic: tac, Techniques: []MitreCell{}}
		for _, c := range cells[tac] {
			col.Techniques = append(col.Techniques, *c)
			col.Count += c.Count
		}
		sort.Slice(col.Techniques, func(i, j int) bool { return col.Techniques[i].Count > col.Techniques[j].Count })
		out = append(out, col)
	}
	return out
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
