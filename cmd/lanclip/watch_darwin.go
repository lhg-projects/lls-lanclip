//go:build darwin

package main

import (
	"time"

	"github.com/lhg-projects/lhg-lanclip/internal/clipboard"
	"github.com/lhg-projects/lhg-lanclip/internal/discovery"
)

var lastPush uint64

// startWatcher polls NSPasteboard changeCount (darwin) and pushes updates.
func startWatcher(srv *serveStack, peers func() []discovery.Peer, stop <-chan struct{}) {
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if u, ok := clipboard.Poll(); ok {
				// content-level dedupe: suppress echo loops where our own
				// pasteboard write races back through the poller
				h := hashUpdate(u)
				if h == lastPush {
					continue
				}
				lastPush = h
				pushClipboard(srv, peers, u)
			}
			time.Sleep(400 * time.Millisecond)
		}
	}()
}
