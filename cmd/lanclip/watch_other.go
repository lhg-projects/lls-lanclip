//go:build !darwin && !windows

package main

import (
	"github.com/lhg-projects/lhg-lanclip/internal/discovery"
	"github.com/lhg-projects/lhg-lanclip/internal/transfer"
)

func startWatcher(*transfer.Engine, func() []discovery.Peer, <-chan struct{}) {}
