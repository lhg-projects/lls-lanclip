// Package settings persists user-facing preferences for the daemon and GUI.
package settings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Toggles gate each clipboard payload kind at push time (WeType's
// deviceSyncModifySwitch is the analogue).
type Settings struct {
	SyncText   bool `json:"sync_text"`
	SyncImages bool `json:"sync_images"`
	SyncFiles  bool `json:"sync_files"`

	// SaveDir and DeviceName are applied on daemon start (changing them in
	// the GUI prompts a restart).
	SaveDir    string `json:"save_dir"`
	DeviceName string `json:"device_name"`
}

// Defaults returns the initial settings for a fresh install.
func Defaults(defaultSaveDir, defaultName string) Settings {
	return Settings{
		SyncText:   true,
		SyncImages: true,
		SyncFiles:  true,
		SaveDir:    defaultSaveDir,
		DeviceName: defaultName,
	}
}

// Store loads/saves the settings JSON and guards in-memory copies.
type Store struct {
	path string

	mu  sync.RWMutex
	cur Settings
}

// Load reads settings from dir/settings.json, creating defaults if missing.
func Load(dir, defaultSaveDir, defaultName string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "settings.json")}
	b, err := os.ReadFile(s.path)
	if err != nil {
		s.cur = Defaults(defaultSaveDir, defaultName)
		if err := s.saveLocked(); err != nil {
			return nil, err
		}
		return s, nil
	}
	def := Defaults(defaultSaveDir, defaultName)
	if err := json.Unmarshal(b, &def); err != nil {
		// corrupted settings must never brick the daemon
		s.cur = Defaults(defaultSaveDir, defaultName)
		_ = s.saveLocked()
		return s, nil
	}
	s.cur = def
	return s, nil
}

// Get returns a snapshot.
func (s *Store) Get() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur
}

// Update applies fn to the current settings and persists atomically.
func (s *Store) Update(fn func(*Settings)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.cur)
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.cur, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
