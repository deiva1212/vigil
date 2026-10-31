package common

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"time"
)

// NewID returns a time-sortable random identifier.
func NewID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return strconv.FormatInt(time.Now().UnixNano(), 36) + hex.EncodeToString(b)
}

// RandomToken returns n random bytes hex-encoded.
func RandomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
