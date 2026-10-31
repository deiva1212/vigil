//go:build windows

package agent

import "os"

func fileOwner(fi os.FileInfo) string { return "" }

// restartSelf exits with code 3; the Windows service recovery settings
// (sc.exe failure ... actions= restart/5000) bring the agent back.
func restartSelf() error {
	os.Exit(3)
	return nil
}
