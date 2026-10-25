//go:build !darwin && !windows

package main

import (
	"github.com/lhg-projects/lhg-lanclip/internal/discovery"
)

// startShotWatcher exists on darwin and windows; other platforms stub.
func startShotWatcher(*serveStack, func() []discovery.Peer, <-chan struct{}) {}
