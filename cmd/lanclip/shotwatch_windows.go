//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/lhg-projects/lhg-lanclip/internal/discovery"
)

// Windows screenshot watcher: Win+PrtScn saves into
// %USERPROFILE%\Pictures\Screenshots without touching the clipboard, so the
// clipboard watcher alone misses them — mirror of the macOS shotwatch.
// Any new settled .png in that folder is treated as a screenshot.
//
// LANCLIP_SHOT_DIR overrides the watched directory (tests/servers).

// startShotWatcher polls dir for settled new PNGs and pushes them to peers.
func startShotWatcher(srv *serveStack, peers func() []discovery.Peer, stop <-chan struct{}) {
	dir := os.Getenv("LANCLIP_SHOT_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return
		}
		dir = filepath.Join(home, "Pictures", "Screenshots")
	}
	_ = os.MkdirAll(dir, 0o755)

	type seen struct {
		size    int64
		modTime time.Time
		sent    bool
	}
	known := map[string]*seen{}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, en := range entries {
			if info, err := en.Info(); err == nil && info.Mode().IsRegular() {
				known[en.Name()] = &seen{size: info.Size(), modTime: info.ModTime(), sent: true}
			}
		}
	}

	fmt.Printf("shotwatch: 监听截图目录 %s（Win+PrtScn 后自动推送给对端）\n", dir)
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if paused.Load() || !syncEnabled("images") {
					continue
				}
				des, err := os.ReadDir(dir)
				if err != nil {
					continue
				}
				for _, de := range des {
					if de.IsDir() || !stringsEqualFold(filepath.Ext(de.Name()), ".png") {
						continue
					}
					info, err := de.Info()
					if err != nil || info.Size() == 0 {
						continue
					}
					st := known[de.Name()]
					if st == nil {
						known[de.Name()] = &seen{size: info.Size(), modTime: info.ModTime()}
						continue
					}
					if st.sent || st.size != info.Size() {
						st.size, st.modTime = info.Size(), info.ModTime()
						continue
					}
					st.sent = true
					pushShotWin(srv, peers, filepath.Join(dir, de.Name()))
				}
				if len(known) > 500 {
					names := make([]string, 0, len(known))
					for n, s := range known {
						if s.sent {
							names = append(names, n)
						}
					}
					sort.Slice(names, func(i, j int) bool { return known[names[i]].modTime.Before(known[names[j]].modTime) })
					for _, n := range names[:len(names)-200] {
						delete(known, n)
					}
				}
			}
		}
	}()
}

func stringsEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func pushShotWin(srv *serveStack, peers func() []discovery.Peer, path string) {
	ps := peers()
	if len(ps) == 0 {
		return
	}
	png, err := os.ReadFile(path)
	if err != nil || len(png) == 0 {
		return
	}
	if n := sendImageTo(srv, ps, png); n > 0 {
		fmt.Printf("shotwatch: 截图 %s (%d KB) 已推送给 %d 台设备\n", filepath.Base(path), len(png)/1024, n)
	}
}
