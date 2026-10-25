//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lhg-projects/lhg-lanclip/internal/discovery"
)

// The user-facing screenshot promise: press ⌘⇧3/⌘⇧4 on this Mac and every
// paired peer can paste it a second later. Normal macOS screenshots land as
// FILES (never touching the clipboard), so the clipboard watcher alone never
// sees them — this poller picks them up from the screencapture location and
// pushes them as image refs (peers paste straight from their clipboards).
//
// LANCLIP_SHOT_DIR overrides the watched directory (tests/servers).

var shotNameRe = regexp.MustCompile(`^(Screen ?[Ss]hot|Screenshot|截屏)[\s\d\-_.]`)

// screenshotDir resolves the directory macOS saves screenshots to.
func screenshotDir() string {
	if d := os.Getenv("LANCLIP_SHOT_DIR"); d != "" {
		return d
	}
	out, err := exec.Command("defaults", "read", "com.apple.screencapture", "location").Output()
	if err == nil {
		if d := strings.TrimSpace(string(out)); d != "" {
			return expandTilde(d)
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Desktop")
}

func expandTilde(p string) string {
	if strings.HasPrefix(p, "~") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	return p
}

// startShotWatcher polls dir for settled new screenshot PNGs and pushes them.
func startShotWatcher(srv *serveStack, peers func() []discovery.Peer, stop <-chan struct{}) {
	dir := screenshotDir()
	_ = os.MkdirAll(dir, 0o755)

	// files already present at startup are history, never pushed
	type seen struct {
		size    int64
		modTime time.Time
		sent    bool
	}
	known := map[string]*seen{}
	entries, _ := os.ReadDir(dir)
	for _, en := range entries {
		if isShotCandidate(en.Name()) {
			if info, err := en.Info(); err == nil {
				known[en.Name()] = &seen{size: info.Size(), modTime: info.ModTime(), sent: true}
			}
		}
	}

	fmt.Printf("shotwatch: 监听截图目录 %s（⌘⇧3/⌘⇧4 后自动推送给对端）\n", dir)
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
				// stable-size check: a fresh screenshot keeps growing briefly
				for _, de := range des {
					name := de.Name()
					if !isShotCandidate(name) || de.IsDir() {
						continue
					}
					info, err := de.Info()
					if err != nil || info.Size() == 0 {
						continue
					}
					st := known[name]
					if st == nil {
						known[name] = &seen{size: info.Size(), modTime: info.ModTime()}
						continue // first sight; wait one round to settle
					}
					if st.sent || st.size != info.Size() {
						st.size, st.modTime = info.Size(), info.ModTime()
						continue
					}
					// settled and unseen: send
					st.sent = true
					pushShot(srv, peers, filepath.Join(dir, name))
				}
				// bound the map
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

func isShotCandidate(name string) bool {
	if !strings.EqualFold(filepath.Ext(name), ".png") {
		return false
	}
	return shotNameRe.MatchString(name)
}

func pushShot(srv *serveStack, peers func() []discovery.Peer, path string) {
	ps := peers()
	if len(ps) == 0 {
		return
	}
	png, err := os.ReadFile(path)
	if err != nil || len(png) == 0 {
		return
	}
	ok := sendImageTo(srv, ps, png)
	if ok > 0 {
		fmt.Printf("shotwatch: 截图 %s (%s KB) 已推送给 %d 台设备\n",
			filepath.Base(path), strconv.FormatInt(int64(len(png))/1024, 10), ok)
	}
}
