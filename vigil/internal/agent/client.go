package agent

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/vigil-siem/vigil/internal/common"
)

var ErrUnauthorized = errors.New("server rejected agent credentials")

type credentials struct {
	AgentID string `json:"agent_id"`
	Token   string `json:"token"`
	Server  string `json:"server"`
}

// Client talks to vigil-server over TLS with optional certificate pinning.
type Client struct {
	cfg  *Config
	http *http.Client
	mu   sync.RWMutex
	cred credentials
}

func NewClient(cfg *Config) (*Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case cfg.ServerFingerprint != "":
		// Pinning: accept exactly one certificate, identified by SHA-256.
		want := cfg.ServerFingerprint
		tc.InsecureSkipVerify = true
		tc.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no server certificate")
			}
			sum := sha256.Sum256(raw[0])
			if got := hex.EncodeToString(sum[:]); got != want {
				return fmt.Errorf("server certificate fingerprint mismatch: got %s", got)
			}
			return nil
		}
	case cfg.CAFile != "":
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates in %s", cfg.CAFile)
		}
		tc.RootCAs = pool
	case cfg.InsecureSkipVerify:
		tc.InsecureSkipVerify = true
	}
	tr := &http.Transport{TLSClientConfig: tc, Proxy: http.ProxyFromEnvironment, MaxIdleConns: 4,
		IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second}
	c := &Client{cfg: cfg, http: &http.Client{Transport: tr, Timeout: 30 * time.Second}}
	c.loadCreds()
	return c, nil
}

func (c *Client) credPath() string { return filepath.Join(c.cfg.StateDir, "credentials.json") }

func (c *Client) loadCreds() {
	b, err := os.ReadFile(c.credPath())
	if err != nil {
		return
	}
	var cr credentials
	if json.Unmarshal(b, &cr) == nil && cr.Server == c.cfg.Server {
		c.cred = cr
	}
}

func (c *Client) AgentID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cred.AgentID
}

func (c *Client) Enrolled() bool { return c.AgentID() != "" }

// Enroll registers with the server using the shared enrollment key.
func (c *Client) Enroll() error {
	if c.cfg.EnrollmentKey == "" {
		return errors.New("enrollment_key is required for first registration")
	}
	host, _ := os.Hostname()
	req := common.EnrollRequest{EnrollmentKey: c.cfg.EnrollmentKey, Name: c.cfg.Name, Hostname: host,
		OS: runtime.GOOS, Arch: runtime.GOARCH, Version: Version, Group: c.cfg.Group}
	var resp common.EnrollResponse
	if err := c.do("POST", "/api/agent/enroll", req, &resp, false); err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	cr := credentials{AgentID: resp.AgentID, Token: resp.Token, Server: c.cfg.Server}
	b, _ := json.Marshal(cr)
	if err := os.WriteFile(c.credPath(), b, 0o600); err != nil {
		return err
	}
	c.mu.Lock()
	c.cred = cr
	c.mu.Unlock()
	return nil
}

// Post sends an authenticated JSON request.
func (c *Client) Post(path string, body, out any) error { return c.do("POST", path, body, out, true) }

// Get sends an authenticated GET.
func (c *Client) Get(path string, out any) error { return c.do("GET", path, nil, out, true) }

func (c *Client) do(method, path string, body, out any, auth bool) error {
	var rd io.Reader
	gz := false
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		if len(b) > 2048 {
			var buf bytes.Buffer
			w := gzip.NewWriter(&buf)
			w.Write(b)
			w.Close()
			rd, gz = &buf, true
		} else {
			rd = bytes.NewReader(b)
		}
	}
	req, err := http.NewRequest(method, c.cfg.Server+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "vigil-agent/"+Version)
	if gz {
		req.Header.Set("Content-Encoding", "gzip")
	}
	if auth {
		c.mu.RLock()
		req.Header.Set("Authorization", "Bearer "+c.cred.AgentID+":"+c.cred.Token)
		c.mu.RUnlock()
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 && auth {
		return ErrUnauthorized
	}
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, bytes.TrimSpace(msg))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}
