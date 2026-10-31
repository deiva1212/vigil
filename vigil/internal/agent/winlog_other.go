//go:build !windows

package agent

// RunWinlog is only implemented on Windows.
func RunWinlog(cfg *Config, ship *Shipper, stop <-chan struct{}) {}
