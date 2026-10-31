//go:build !windows

package agent

import (
	"os"
	"strconv"
	"syscall"
)

func fileOwner(fi os.FileInfo) string {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return strconv.FormatUint(uint64(st.Uid), 10) + ":" + strconv.FormatUint(uint64(st.Gid), 10)
	}
	return ""
}

// restartSelf re-executes the agent binary in place (keeps the PID).
func restartSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}
