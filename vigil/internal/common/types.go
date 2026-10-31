// Package common holds the wire types shared by the Vigil agent and server.
package common

import "time"

// Event is a single normalized security event shipped by an agent.
// Fields is a flat key/value map that Sigma rules match against
// (e.g. "message", "process.name", "user.name", "source.ip", "file.path").
type Event struct {
	ID        string            `json:"id"`
	AgentID   string            `json:"agent_id"`
	Hostname  string            `json:"hostname"`
	Timestamp time.Time         `json:"timestamp"`
	Category  string            `json:"category"` // log | fim | process | inventory | sca | network | response
	Source    string            `json:"source"`   // e.g. /var/log/auth.log, fim, sca
	Fields    map[string]string `json:"fields"`
	Raw       string            `json:"raw,omitempty"`
}

// Alert is produced by the server when a rule matches one or more events.
type Alert struct {
	ID          string            `json:"id"`
	RuleID      string            `json:"rule_id"`
	RuleTitle   string            `json:"rule_title"`
	Level       string            `json:"level"` // informational | low | medium | high | critical
	Score       int               `json:"score"` // 0-100 numeric severity
	AgentID     string            `json:"agent_id"`
	Hostname    string            `json:"hostname"`
	Timestamp   time.Time         `json:"timestamp"`
	Description string            `json:"description"`
	Tags        []string          `json:"tags"`
	MITRE       []string          `json:"mitre"`      // e.g. T1110, TA0006
	Compliance  []string          `json:"compliance"` // e.g. PCI-DSS 10.2.4
	EventIDs    []string          `json:"event_ids"`
	Fields      map[string]string `json:"fields"`
	Status      string            `json:"status"` // open | acknowledged | closed
	Kind        string            `json:"kind"`   // sigma | correlation | vulnerability | sca | system
	Count       int               `json:"count"`  // occurrences folded into this alert (dedup)
	LastSeen    time.Time         `json:"last_seen"`
	Note        string            `json:"note,omitempty"`
	Response    string            `json:"response,omitempty"` // id of an automatic response command
}

// AgentInfo is what the server tracks about an enrolled endpoint.
type AgentInfo struct {
	ID           string           `json:"id"`
	Name         string           `json:"name"`
	Hostname     string           `json:"hostname"`
	OS           string           `json:"os"`
	Arch         string           `json:"arch"`
	IP           string           `json:"ip"`
	Version      string           `json:"version"`
	Group        string           `json:"group"`
	EnrolledAt   time.Time        `json:"enrolled_at"`
	LastSeen     time.Time        `json:"last_seen"`
	Status       string           `json:"status"` // active | disconnected | never_connected
	TokenHash    string           `json:"token_hash,omitempty"`
	EventCount   int64            `json:"event_count"`
	SCAScore     int              `json:"sca_score"` // % of passed config checks
	PackageCount int              `json:"package_count"`
	VulnCount    int              `json:"vuln_count"`
	Health       HeartbeatRequest `json:"health"`
}

// EnrollRequest is sent once by a new agent with the shared enrollment key.
type EnrollRequest struct {
	EnrollmentKey string `json:"enrollment_key"`
	Name          string `json:"name"`
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	Version       string `json:"version"`
	Group         string `json:"group"`
}

// EnrollResponse returns the per-agent identity and bearer token.
type EnrollResponse struct {
	AgentID string `json:"agent_id"`
	Token   string `json:"token"`
}

// EventBatch is the ingestion payload.
type EventBatch struct {
	Events []Event `json:"events"`
}

// Package is one installed software package (for vulnerability detection).
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source"` // dpkg | rpm | apk | brew | windows
}

// Inventory is a periodic snapshot of host state.
type Inventory struct {
	AgentID   string    `json:"agent_id"`
	Timestamp time.Time `json:"timestamp"`
	Packages  []Package `json:"packages"`
	Processes []Process `json:"processes"`
	Ports     []Port    `json:"ports"`
	OSRelease string    `json:"os_release"`
	Kernel    string    `json:"kernel"`
	Users     []string  `json:"users"`
}

type Process struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	Name    string `json:"name"`
	Cmdline string `json:"cmdline"`
	User    string `json:"user"`
}

type Port struct {
	Protocol string `json:"protocol"`
	Local    string `json:"local"`
	State    string `json:"state"`
	PID      int    `json:"pid,omitempty"`
}

// SCAResult is one Security Configuration Assessment check outcome.
type SCAResult struct {
	CheckID    string   `json:"check_id"`
	Title      string   `json:"title"`
	Result     string   `json:"result"` // passed | failed | not_applicable
	Rationale  string   `json:"rationale"`
	Remedy     string   `json:"remediation"`
	Compliance []string `json:"compliance"`
}

// SCAReport is a full SCA run from an agent.
type SCAReport struct {
	AgentID   string      `json:"agent_id"`
	Policy    string      `json:"policy"`
	Timestamp time.Time   `json:"timestamp"`
	Results   []SCAResult `json:"results"`
}

// Command is an active-response action queued by the server for an agent.
type Command struct {
	ID        string            `json:"id"`
	AgentID   string            `json:"agent_id"`
	Action    string            `json:"action"` // block_ip | unblock_ip | kill_process | quarantine_file | restart_agent | collect_file
	Args      map[string]string `json:"args"`
	CreatedAt time.Time         `json:"created_at"`
	CreatedBy string            `json:"created_by"` // admin | rule:<id>
	Status    string            `json:"status"`     // pending | delivered | succeeded | failed
	Result    string            `json:"result"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// CommandResult is posted back by an agent after executing a command.
type CommandResult struct {
	CommandID string `json:"command_id"`
	Status    string `json:"status"`
	Output    string `json:"output"`
}

// HeartbeatRequest reports agent health.
type HeartbeatRequest struct {
	Version    string `json:"version"`
	QueueLen   int    `json:"queue_len"`
	Spooled    int64  `json:"spooled"`
	Dropped    int64  `json:"dropped"`
	Sent       int64  `json:"sent"`
	UptimeSec  int64  `json:"uptime_sec"`
	FIMFiles   int    `json:"fim_files"`
	LogSources int    `json:"log_sources"`
	IP         string `json:"ip"`
}

// HeartbeatResponse carries pending commands and config hints to the agent.
type HeartbeatResponse struct {
	Commands      []Command `json:"commands"`
	ServerTime    time.Time `json:"server_time"`
	ConfigVersion int       `json:"config_version"`
}

// LevelScore converts a Sigma level into a numeric score.
func LevelScore(level string) int {
	switch level {
	case "critical":
		return 95
	case "high":
		return 75
	case "medium":
		return 50
	case "low":
		return 25
	default:
		return 10
	}
}
