package settings

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCreatesDefaults(t *testing.T) {
	dir := t.TempDir()
	s, err := Load(dir, filepath.Join(dir, "received"), "My-Mac")
	if err != nil {
		t.Fatal(err)
	}
	got := s.Get()
	if !got.SyncText || !got.SyncImages || !got.SyncFiles {
		t.Fatalf("defaults should enable all sync toggles: %+v", got)
	}
	if got.SaveDir != filepath.Join(dir, "received") || got.DeviceName != "My-Mac" {
		t.Fatalf("bad defaults: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "settings.json")); err != nil {
		t.Fatalf("settings.json not written: %v", err)
	}
}

func TestUpdatePersists(t *testing.T) {
	dir := t.TempDir()
	s, _ := Load(dir, "d", "n")
	if err := s.Update(func(c *Settings) { c.SyncFiles = false; c.DeviceName = "renamed" }); err != nil {
		t.Fatal(err)
	}
	s2, _ := Load(dir, "d", "n")
	g := s2.Get()
	if g.SyncFiles || g.DeviceName != "renamed" {
		t.Fatalf("update not persisted: %+v", g)
	}
}

func TestCorruptedFileFallsBack(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "settings.json"), []byte("{not json"), 0o600)
	s, err := Load(dir, "d", "n")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Get().SyncText {
		t.Fatal("corrupt settings should fall back to defaults")
	}
}
