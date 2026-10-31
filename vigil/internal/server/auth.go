package server

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vigil-siem/vigil/internal/common"
)

// Roles: viewer (read-only), analyst (triage + response), admin (everything).
var roleRank = map[string]int{"viewer": 1, "analyst": 2, "admin": 3}

type User struct {
	Username string    `json:"username"`
	Role     string    `json:"role"`
	Salt     string    `json:"salt"`
	Hash     string    `json:"hash"`
	Created  time.Time `json:"created"`
}

type session struct {
	user    string
	role    string
	expires time.Time
}

// Auth manages dashboard users, sessions and login throttling.
type Auth struct {
	mu       sync.Mutex
	path     string
	users    map[string]*User
	sessions map[string]*session
	failures map[string][]time.Time
}

const pbkdf2Iter = 210000

// pbkdf2SHA256 implements RFC 8018 PBKDF2 with HMAC-SHA256 (stdlib only).
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hLen := prf.Size()
	blocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)
	buf := make([]byte, 4)
	for b := 1; b <= blocks; b++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf, uint32(b))
		prf.Write(buf)
		u := prf.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for x := range t {
				t[x] ^= u[x]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

func hashPassword(pw, saltHex string) string {
	salt, _ := hex.DecodeString(saltHex)
	return hex.EncodeToString(pbkdf2SHA256([]byte(pw), salt, pbkdf2Iter, 32))
}

// NewAuth loads users; creates the admin user on first run.
func NewAuth(dataDir, initialPassword string) (*Auth, error) {
	a := &Auth{path: filepath.Join(dataDir, "users.json"), users: map[string]*User{},
		sessions: map[string]*session{}, failures: map[string][]time.Time{}}
	if b, err := os.ReadFile(a.path); err == nil {
		var list []*User
		if err := json.Unmarshal(b, &list); err != nil {
			return nil, fmt.Errorf("users.json: %w", err)
		}
		for _, u := range list {
			a.users[u.Username] = u
		}
	}
	if len(a.users) == 0 {
		pw := initialPassword
		generated := pw == ""
		if generated {
			pw = common.RandomToken(9)
		}
		if err := a.CreateUser("admin", pw, "admin"); err != nil {
			return nil, err
		}
		if generated {
			f := filepath.Join(dataDir, "initial-admin-password.txt")
			_ = os.WriteFile(f, []byte(pw+"\n"), 0o600)
			log.Printf("auth: created user 'admin' with password %s (also saved to %s — delete it after first login)", pw, f)
		} else {
			log.Printf("auth: created user 'admin' with the configured password")
		}
	}
	return a, nil
}

func (a *Auth) save() error {
	list := make([]*User, 0, len(a.users))
	for _, u := range a.users {
		list = append(list, u)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Username < list[j].Username })
	b, _ := json.MarshalIndent(list, "", "  ")
	return os.WriteFile(a.path, b, 0o600)
}

func (a *Auth) CreateUser(name, pw, role string) error {
	if _, ok := roleRank[role]; !ok {
		return errors.New("role must be viewer, analyst or admin")
	}
	if len(pw) < 10 {
		return errors.New("password must be at least 10 characters")
	}
	if name == "" || strings.ContainsAny(name, " /:") {
		return errors.New("invalid username")
	}
	salt := common.RandomToken(16)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.users[name] = &User{Username: name, Role: role, Salt: salt, Hash: hashPassword(pw, salt), Created: time.Now()}
	return a.save()
}

func (a *Auth) DeleteUser(name string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.users[name]; !ok {
		return errors.New("no such user")
	}
	admins := 0
	for _, u := range a.users {
		if u.Role == "admin" {
			admins++
		}
	}
	if a.users[name].Role == "admin" && admins == 1 {
		return errors.New("cannot delete the last admin")
	}
	delete(a.users, name)
	for t, s := range a.sessions {
		if s.user == name {
			delete(a.sessions, t)
		}
	}
	return a.save()
}

func (a *Auth) Users() []map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []map[string]any
	for _, u := range a.users {
		out = append(out, map[string]any{"username": u.Username, "role": u.Role, "created": u.Created})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["username"].(string) < out[j]["username"].(string) })
	return out
}

var errThrottled = errors.New("too many failed attempts; try again in a few minutes")

// Login verifies credentials with per-IP throttling (5 failures / 5 min).
func (a *Auth) Login(name, pw, ip string) (string, *User, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	var recent []time.Time
	for _, t := range a.failures[ip] {
		if now.Sub(t) < 5*time.Minute {
			recent = append(recent, t)
		}
	}
	a.failures[ip] = recent
	if len(recent) >= 5 {
		return "", nil, errThrottled
	}
	u := a.users[name]
	ok := false
	if u != nil {
		ok = subtle.ConstantTimeCompare([]byte(hashPassword(pw, u.Salt)), []byte(u.Hash)) == 1
	} else {
		hashPassword(pw, "00") // equalise timing for unknown users
	}
	if !ok {
		a.failures[ip] = append(a.failures[ip], now)
		return "", nil, errors.New("invalid username or password")
	}
	delete(a.failures, ip)
	tok := common.RandomToken(32)
	a.sessions[tok] = &session{user: u.Username, role: u.Role, expires: now.Add(12 * time.Hour)}
	return tok, u, nil
}

func (a *Auth) Logout(tok string) {
	a.mu.Lock()
	delete(a.sessions, tok)
	a.mu.Unlock()
}

// Session resolves a bearer token.
func (a *Auth) Session(tok string) (string, string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.sessions[tok]
	if s == nil || time.Now().After(s.expires) {
		delete(a.sessions, tok)
		return "", "", false
	}
	return s.user, s.role, true
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// TokenHash hashes an agent token for storage.
func TokenHash(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// ------------------------------------------------------------------- audit

type AuditEntry struct {
	Time    time.Time         `json:"time"`
	User    string            `json:"user"`
	Action  string            `json:"action"`
	Target  string            `json:"target"`
	Details map[string]string `json:"details,omitempty"`
}

// Audit is an append-only log of administrative actions.
type Audit struct {
	mu     sync.Mutex
	f      *os.File
	recent []AuditEntry
}

func NewAudit(dataDir string) (*Audit, error) {
	p := filepath.Join(dataDir, "audit.jsonl")
	a := &Audit{}
	if f, err := os.Open(p); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var e AuditEntry
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				a.recent = append(a.recent, e)
				if len(a.recent) > 2000 {
					a.recent = a.recent[1000:]
				}
			}
		}
		f.Close()
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	a.f = f
	return a, nil
}

func (a *Audit) Log(user, action, target string, details map[string]string) {
	e := AuditEntry{Time: time.Now(), User: user, Action: action, Target: target, Details: details}
	b, _ := json.Marshal(e)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.f.Write(append(b, '\n'))
	a.recent = append(a.recent, e)
	if len(a.recent) > 2000 {
		a.recent = a.recent[1000:]
	}
}

func (a *Audit) Recent(n int) []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []AuditEntry
	for i := len(a.recent) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, a.recent[i])
	}
	return out
}
