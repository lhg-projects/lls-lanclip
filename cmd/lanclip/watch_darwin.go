//go:build darwin

package main

import (
	"time"

	"github.com/lhg-projects/lhg-lanclip/internal/clipboard"
	"github.com/lhg-projects/lhg-lanclip/internal/discovery"
	"github.com/lhg-projects/lhg-lanclip/internal/transfer"
)

var lastPush uint64

// startWatcher polls NSPasteboard changeCount (darwin) and pushes updates.
func startWatcher(e *transfer.Engine, peers func() []discovery.Peer, stop <-chan struct{}) {
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
				pushClipboard(e, peers, u)
			}
			time.Sleep(400 * time.Millisecond)
		}
	}()
}
