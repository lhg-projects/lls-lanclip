//go:build windows

package main

import (
	"github.com/lhg-projects/lhg-lanclip/internal/clipboard"
	"github.com/lhg-projects/lhg-lanclip/internal/discovery"
)

// startWatcher uses the push-based Windows clipboard listener.
func startWatcher(srv *serveStack, peers func() []discovery.Peer, stop <-chan struct{}) {
	if _, err := clipboard.NewWatcher(func(u clipboard.Update) {
		pushClipboard(srv, peers, u)
	}); err != nil {
		println("clipboard watcher:", err.Error())
	}
}
