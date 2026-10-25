//go:build !darwin && !windows

package main

import (
	"github.com/lhg-projects/lhg-lanclip/internal/discovery"
)

func startWatcher(*serveStack, func() []discovery.Peer, <-chan struct{}) {}
