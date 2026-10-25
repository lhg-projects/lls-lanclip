//go:build !darwin && !windows

package main

import (
	"sync/atomic"

	"github.com/lhg-projects/lhg-lanclip/internal/discovery"
	"github.com/lhg-projects/lhg-lanclip/internal/transfer"
)

// runTray is a no-op on platforms without a tray (headless linux servers);
// serve falls back to plain signal handling.
func runTray(*transfer.Engine, func() []discovery.Peer, *atomic.Bool) {}

// traySupported reports whether this build shows a tray at all.
func traySupported() bool { return false }
