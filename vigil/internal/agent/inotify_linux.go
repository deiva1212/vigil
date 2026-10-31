//go:build linux

package agent

import (
	"io/fs"
	"log"
	"path/filepath"
	"syscall"
	"unsafe"
)

const maxWatches = 8192

// watchRealtime uses inotify to push changed paths to the FIM checker
// within about a second, between periodic full scans.
func watchRealtime(roots []string, ignored func(string) bool, out chan<- string, stop <-chan struct{}) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC)
	if err != nil {
		log.Printf("fim: inotify unavailable: %v", err)
		return
	}
	defer syscall.Close(fd)
	const mask = syscall.IN_CLOSE_WRITE | syscall.IN_CREATE | syscall.IN_DELETE | syscall.IN_MOVED_FROM |
		syscall.IN_MOVED_TO | syscall.IN_ATTRIB | syscall.IN_DELETE_SELF
	wds := map[int32]string{}
	add := func(dir string) {
		if len(wds) >= maxWatches || ignored(dir) {
			return
		}
		wd, err := syscall.InotifyAddWatch(fd, dir, mask)
		if err == nil {
			wds[int32(wd)] = dir
		}
	}
	for _, r := range roots {
		filepath.WalkDir(r, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				if ignored(p) {
					return filepath.SkipDir
				}
				add(p)
			}
			return nil
		})
	}
	log.Printf("fim: realtime watching %d directories", len(wds))
	go func() { <-stop; syscall.Close(fd) }()
	buf := make([]byte, 64*1024)
	for {
		n, err := syscall.Read(fd, buf)
		if err != nil || n <= 0 {
			return
		}
		for off := 0; off+syscall.SizeofInotifyEvent <= n; {
			ev := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[off]))
			nameLen := int(ev.Len)
			name := ""
			if nameLen > 0 {
				nb := buf[off+syscall.SizeofInotifyEvent : off+syscall.SizeofInotifyEvent+nameLen]
				for i, c := range nb {
					if c == 0 {
						nb = nb[:i]
						break
					}
				}
				name = string(nb)
			}
			off += syscall.SizeofInotifyEvent + nameLen
			dir, ok := wds[ev.Wd]
			if !ok || name == "" {
				continue
			}
			p := filepath.Join(dir, name)
			if ev.Mask&syscall.IN_ISDIR != 0 {
				if ev.Mask&(syscall.IN_CREATE|syscall.IN_MOVED_TO) != 0 {
					add(p)
				}
				continue
			}
			select {
			case out <- p:
			default:
			}
		}
	}
}
