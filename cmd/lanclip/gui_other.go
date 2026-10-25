//go:build !darwin

package main

// guiSupported: the Fyne panel is darwin-only for now; Windows/Linux keep
// the headless + systray daemon (their CI lacks cgo GUI toolchains).
func guiSupported() bool { return false }

// runGUI is unreachable on these platforms (guarded by guiSupported).
func runGUI(*serveStack, bool) {}
