//go:build !linux

package agent

// watchRealtime is a no-op off Linux; periodic scans still run.
// (macOS FSEvents / Windows ReadDirectoryChangesW are natural next steps.)
func watchRealtime(roots []string, ignored func(string) bool, out chan<- string, stop <-chan struct{}) {
}
