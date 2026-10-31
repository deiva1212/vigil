package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// EnsureCert returns cert/key paths, generating a self-signed ECDSA
// certificate on first run. Agents pin its SHA-256 fingerprint, so a
// self-signed certificate is safe to use without a public CA.
func EnsureCert(cfg *Config) (string, string, error) {
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		return cfg.CertFile, cfg.KeyFile, nil
	}
	cert := filepath.Join(cfg.DataDir, "tls", "server.crt")
	key := filepath.Join(cfg.DataDir, "tls", "server.key")
	if _, err := os.Stat(cert); err == nil {
		return cert, key, nil
	}
	if err := os.MkdirAll(filepath.Dir(cert), 0o700); err != nil {
		return "", "", err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	host, _ := os.Hostname()
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "vigil-server", Organization: []string{"Vigil"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(3, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", host, "vigil-server"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() {
				tpl.IPAddresses = append(tpl.IPAddresses, ipn.IP)
			}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}
	kb, _ := x509.MarshalECPrivateKey(priv)
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return "", "", err
	}
	log.Printf("tls: generated self-signed certificate %s", cert)
	return cert, key, nil
}

// CertFingerprint returns the SHA-256 fingerprint of the leaf certificate.
func CertFingerprint(certFile, keyFile string) (string, error) {
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return "", err
	}
	if len(c.Certificate) == 0 {
		return "", fmt.Errorf("no certificate")
	}
	sum := sha256.Sum256(c.Certificate[0])
	return hex.EncodeToString(sum[:]), nil
}
