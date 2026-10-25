// Package discovery advertises and finds lanclip peers on the LAN via mDNS
// (Bonjour/zeroconf), the no-backend replacement for WeType's account-based
// device binding (match code → server group registry).
package discovery

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grandcat/zeroconf"
)

// Peer is a discovered lanclip instance.
type Peer struct {
	DeviceID   string
	DeviceName string
	Platform   string
	Addr       string // host:port of the TLS listener
}

// TXT keys.
const (
	txtDeviceID = "id"
	txtPlatform = "pt"
	txtVersion  = "ver"
)

// Announcer advertises this device until closed.
type Announcer struct {
	server *zeroconf.Server
}

// Announce starts mDNS advertising on all interfaces.
func Announce(deviceID, deviceName, platform, version string, port int) (*Announcer, error) {
	server, err := zeroconf.Register(
		deviceName,        // instance name
		protocolService(), // service type
		"local.",          // domain
		port,
		[]string{fmt.Sprintf("%s=%s", txtDeviceID, deviceID), fmt.Sprintf("%s=%s", txtPlatform, platform), fmt.Sprintf("%s=%s", txtVersion, version)},
		nil, // all interfaces
	)
	if err != nil {
		return nil, err
	}
	return &Announcer{server: server}, nil
}

// Close stops advertising.
func (a *Announcer) Close() { a.server.Shutdown() }

func protocolService() string { return "_lanclip._tcp" }

// Browser finds peers. It continuously refreshes; peer list is deduped by ID.
type Browser struct {
	mu    sync.RWMutex
	peers map[string]Peer

	cancel context.CancelFunc
}

// NewBrowser starts browsing in the background.
func NewBrowser() *Browser {
	ctx, cancel := context.WithCancel(context.Background())
	b := &Browser{peers: map[string]Peer{}, cancel: cancel}
	go b.run(ctx)
	return b
}

func (b *Browser) run(ctx context.Context) {
	for ctx.Err() == nil {
		resolver, err := zeroconf.NewResolver(nil)
		if err != nil {
			sleepCtx(ctx, 3*time.Second)
			continue
		}
		entries := make(chan *zeroconf.ServiceEntry, 32)
		go func() {
			for e := range entries {
				if e == nil {
					continue
				}
				p := entryToPeer(e)
				if p.DeviceID == "" || p.Addr == "" {
					continue
				}
				b.mu.Lock()
				b.peers[p.DeviceID] = p
				b.mu.Unlock()
			}
		}()
		_ = resolver.Browse(ctx, protocolService(), "local.", entries)
		// Browse returns when ctx cancels or errors; refresh periodically so
		// newly joined devices are found even if mDNS cache went stale.
		sleepCtx(ctx, 5*time.Second)
	}
}

func entryToPeer(e *zeroconf.ServiceEntry) Peer {
	p := Peer{DeviceName: strings.TrimSuffix(e.Service, "."+protocolService())}
	for _, t := range e.Text {
		k, v, _ := strings.Cut(t, "=")
		switch k {
		case txtDeviceID:
			p.DeviceID = v
		case txtPlatform:
			p.Platform = v
		}
	}
	if e.Port > 0 {
		host := ""
		if len(e.AddrIPv4) > 0 {
			host = e.AddrIPv4[0].String()
		} else if len(e.AddrIPv6) > 0 {
			host = "[" + e.AddrIPv6[0].String() + "]"
		} else if e.HostName != "" {
			host = strings.TrimSuffix(e.HostName, ".")
		}
		if host != "" {
			p.Addr = net.JoinHostPort(host, strconv.Itoa(e.Port))
		}
	}
	return p
}

// Peers returns the current snapshot.
func (b *Browser) Peers() []Peer {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]Peer, 0, len(b.peers))
	for _, p := range b.peers {
		out = append(out, p)
	}
	return out
}

// Stop terminates browsing.
func (b *Browser) Stop() { b.cancel() }

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
