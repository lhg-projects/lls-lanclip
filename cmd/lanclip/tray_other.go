//go:build !darwin && !windows

package main

import (
	"sync/atomic"
)

// runTray is a no-op on platforms without a tray (headless linux servers);
// serve falls back to plain signal handling.
func runTray(*serveStack, *atomic.Bool) {}

// traySupported reports whether this build shows a tray at all.
func traySupported() bool { return false }
