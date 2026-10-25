//go:build !darwin

package main

import (
	"github.com/lhg-projects/lhg-lanclip/internal/discovery"
	"github.com/lhg-projects/lhg-lanclip/internal/transfer"
)

// startShotWatcher is macOS-only for now; Windows screenshots can be wired
// the same way (watch %USERPROFILE%\Videos\Captures / PrintScreen folder)
// once real-machine testing begins.
func startShotWatcher(*transfer.Engine, func() []discovery.Peer, <-chan struct{}) {}
