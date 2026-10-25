package api

import (
	"sync"
	"time"
)

// Item is one inbox entry surfaced to HTTP clients (phones polling for what
// the desktop received, or UIs replaying recent activity).
type Item struct {
	ID      int64  `json:"id"`
	TS      int64  `json:"ts"`
	Kind    string `json:"kind"` // text | image | file
	From    string `json:"from"`
	Text    string `json:"text,omitempty"`
	Name    string `json:"name,omitempty"`
	Size    int64  `json:"size,omitempty"`
	FileURL string `json:"file_url,omitempty"` // desktop->phone file download
}

// Inbox is a bounded in-memory ring of recent received events.
type Inbox struct {
	mu    sync.RWMutex
	items []Item
	next  int64
}

// NewInbox returns a ring keeping the latest max entries.
func NewInbox(max int) *Inbox {
	if max <= 0 {
		max = 100
	}
	return &Inbox{items: make([]Item, 0, max), next: 1}
}

// Add appends an entry and returns its ID.
func (in *Inbox) Add(kind, from, text, name string, size int64, fileURL string) int64 {
	in.mu.Lock()
	defer in.mu.Unlock()
	id := in.next
	in.next++
	in.items = append(in.items, Item{
		ID: id, TS: time.Now().UnixMilli(), Kind: kind, From: from,
		Text: text, Name: name, Size: size, FileURL: fileURL,
	})
	if len(in.items) > cap(in.items) {
		in.items = in.items[1:]
	}
	return id
}

// Since returns entries newer than id (oldest first).
func (in *Inbox) Since(id int64) []Item {
	in.mu.RLock()
	defer in.mu.RUnlock()
	out := make([]Item, 0, 8)
	for _, it := range in.items {
		if it.ID > id {
			out = append(out, it)
		}
	}
	return out
}
