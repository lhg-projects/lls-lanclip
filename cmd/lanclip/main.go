// Command lanclip is a serverless LAN clipboard & file sync tool
// (text + screenshots + copied files across macOS/Windows devices).
//
// Commands:
//
//	lanclip serve              run the daemon: advertise, discover, sync clipboard
//	lanclip peers              list discovered peers
//	lanclip send-text TEXT     send text to peers now
//	lanclip send-file PATH...  send file(s) to peers now
//	lanclip pin                show the pairing PIN derived from the group key
//	lanclip key-export         print group key (base64) for pairing a new device
//	lanclip key-import BASE64  adopt the group key printed by key-export
//	lanclip pair-advertise     one-tap PIN pairing: show PIN and wait
//	lanclip pair HOST[:port]   one-tap PIN pairing: join by typing the PIN
//	lanclip version
//
// Environment:
//
//	LANCLIP_DIR          config/state directory (default: platform default)
//	LANCLIP_PORT         sync listener port (default 47717)
//	LANCLIP_API_PORT     optional local HTTP API port (peers/send-text/shot)
//	LANCLIP_PEERS        comma-separated static peer addresses; used in
//	                     addition to mDNS discovery (and as fallback in
//	                     sandboxes where mDNS is unavailable)
//	LANCLIP_INSECURE_OPEN=1  accept unpaired LAN devices (NOT recommended)
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/lhg-projects/lhg-lanclip/internal/clipboard"
	"github.com/lhg-projects/lhg-lanclip/internal/crypto"
	"github.com/lhg-projects/lhg-lanclip/internal/discovery"
	"github.com/lhg-projects/lhg-lanclip/internal/pair"
	"github.com/lhg-projects/lhg-lanclip/internal/protocol"
	"github.com/lhg-projects/lhg-lanclip/internal/transfer"
)

const appVersion = "0.3.0"

// paused gates outbound clipboard pushes (toggled from the tray menu).
var paused atomic.Bool

func configDir() string {
	if d := os.Getenv("LANCLIP_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "lanclip")
}

func loadOrCreateGroupKey() ([]byte, error) {
	dir := configDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "group.key")
	if b, err := os.ReadFile(path); err == nil && len(b) == crypto.GroupKeyLen {
		return b, nil
	}
	k, err := crypto.NewGroupKey()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, k, 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

func loadOrCreateDeviceID() string {
	idPath := filepath.Join(configDir(), "device.id")
	if b, err := os.ReadFile(idPath); err == nil && len(b) == 32 {
		return string(b)
	}
	id := crypto.NewDeviceID()
	_ = os.WriteFile(idPath, []byte(id), 0o600)
	return id
}

func deviceName() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		h = "unknown-host"
	}
	return h
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	key, err := loadOrCreateGroupKey()
	if err != nil {
		fatal(err)
	}
	deviceID := loadOrCreateDeviceID()

	switch cmd {
	case "serve":
		runServe(key, deviceID)
	case "peers":
		b := discovery.NewBrowser()
		time.Sleep(1500 * time.Millisecond)
		for _, p := range staticAndDiscovered(b) {
			id := p.DeviceID
			if len(id) > 8 {
				id = id[:8]
			}
			fmt.Printf("%s\t%s\t%s\t%s\n", p.DeviceName, id, p.Platform, p.Addr)
		}
	case "send-text":
		if len(os.Args) < 3 {
			fatal(fmt.Errorf("usage: lanclip send-text TEXT"))
		}
		text := strings.Join(os.Args[2:], " ")
		sendToPeers(key, deviceID, func(addr string, e *transfer.Engine) error {
			return e.SendText(addr, text)
		})
	case "send-file":
		if len(os.Args) < 3 {
			fatal(fmt.Errorf("usage: lanclip send-file PATH [PATH...]"))
		}
		sendToPeers(key, deviceID, func(addr string, e *transfer.Engine) error {
			return e.SendFiles(addr, os.Args[2:])
		})
	case "pin":
		pin, err := crypto.DerivePINBytes(key)
		if err != nil {
			fatal(err)
		}
		fmt.Println(pin)
	case "key-export":
		// pairing step 1 (on the already-paired device): print the group key
		fmt.Println(base64.StdEncoding.EncodeToString(key))
	case "key-import":
		// pairing step 2 (on the new device): lanclip key-import <b64>
		if len(os.Args) < 3 {
			fatal(fmt.Errorf("usage: lanclip key-import BASE64 (from `lanclip key-export` on the paired device)"))
		}
		k, err := base64.StdEncoding.DecodeString(os.Args[2])
		if err != nil || len(k) != crypto.GroupKeyLen {
			fatal(fmt.Errorf("invalid key material"))
		}
		path := filepath.Join(configDir(), "group.key")
		if err := os.MkdirAll(configDir(), 0o700); err != nil {
			fatal(err)
		}
		if err := os.WriteFile(path, k, 0o600); err != nil {
			fatal(err)
		}
		pin, _ := crypto.DerivePINBytes(k)
		fmt.Printf("imported; pairing PIN is now %s (must match the other device)\n", pin)
	case "key-hex":
		fmt.Println(hex.EncodeToString(key))
	case "pair-advertise":
		if err := pair.Listen(key, deviceID, deviceName(), printfStdout); err != nil {
			fatal(err)
		}
	case "pair":
		if len(os.Args) < 3 {
			fatal(fmt.Errorf("usage: lanclip pair HOST[:port]   (port defaults to %d)", pair.Port))
		}
		addr := os.Args[2]
		if !strings.Contains(addr, ":") {
			addr = fmt.Sprintf("%s:%d", addr, pair.Port)
		}
		fmt.Print("请输入对方屏幕上显示的 6 位 PIN: ")
		var pinCode string
		if _, err := fmt.Scanln(&pinCode); err != nil {
			fatal(err)
		}
		gk, err := pair.Join(addr, pinCode, deviceID, deviceName())
		if err != nil {
			fatal(err)
		}
		path := filepath.Join(configDir(), "group.key")
		if err := os.WriteFile(path, gk, 0o600); err != nil {
			fatal(err)
		}
		pin, _ := crypto.DerivePINBytes(gk)
		fmt.Printf("配对成功，本机 PIN 已变为 %s（与对方一致即正确）\n", pin)
	case "version":
		fmt.Println(appVersion)
	default:
		usage()
		os.Exit(2)
	}
}

func printfStdout(format string, args ...any) { fmt.Printf(format+"\n", args...) }

func usage() {
	fmt.Fprint(os.Stderr, `lanclip — serverless LAN clipboard & file sync

Usage:
  lanclip serve                  run the sync daemon
  lanclip peers                  list discovered peers
  lanclip send-text TEXT         send text to peers
  lanclip send-file PATH...      send files to peers
  lanclip pin                    show pairing PIN (must match on both devices)
  lanclip key-export             print group key (base64) for pairing
  lanclip key-import BASE64      adopt the group key printed by key-export
  lanclip pair-advertise         one-tap PIN pairing (this device shows PIN)
  lanclip pair HOST[:port]       one-tap PIN pairing (this device joins)
  lanclip version

Env: LANCLIP_DIR, LANCLIP_PORT, LANCLIP_API_PORT, LANCLIP_PEERS
`)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "lanclip:", err)
	os.Exit(1)
}

// staticPeers returns LANCLIP_PEERS as addresses.
func staticPeers() []string {
	v := strings.TrimSpace(os.Getenv("LANCLIP_PEERS"))
	if v == "" {
		return nil
	}
	var out []string
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// staticAndDiscovered merges static peers with mDNS results (deduped by addr).
func staticAndDiscovered(b *discovery.Browser) []discovery.Peer {
	seen := map[string]bool{}
	var out []discovery.Peer
	for _, p := range b.Peers() {
		if !seen[p.Addr] {
			seen[p.Addr] = true
			out = append(out, p)
		}
	}
	for _, a := range staticPeers() {
		if !seen[a] {
			seen[a] = true
			out = append(out, discovery.Peer{DeviceName: "static", DeviceID: "static000", Platform: "?", Addr: a})
		}
	}
	return out
}

// sendToPeers resolves peers (static first, else mDNS) and runs fn on each.
func sendToPeers(groupKey []byte, deviceID string, fn func(addr string, e *transfer.Engine) error) {
	e, err := transfer.NewEngine(transfer.Config{
		DeviceID:   deviceID,
		DeviceName: deviceName(),
		Platform:   runtime.GOOS,
		Version:    appVersion,
		GroupKey:   groupKey,
		SaveDir:    filepath.Join(configDir(), "received"),
	})
	if err != nil {
		fatal(err)
	}
	targets := staticPeers()
	if len(targets) == 0 {
		b := discovery.NewBrowser()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) && len(targets) == 0 {
			var addrs []string
			for _, p := range b.Peers() {
				if p.DeviceID != deviceID {
					addrs = append(addrs, p.Addr)
				}
			}
			targets = addrs
			if len(targets) == 0 {
				time.Sleep(200 * time.Millisecond)
			}
		}
		b.Stop()
	}
	if len(targets) == 0 {
		fatal(fmt.Errorf("no peer found on this network (is 'lanclip serve' running on the other device?)"))
	}
	sent := 0
	for _, addr := range targets {
		if err := fn(addr, e); err != nil {
			fmt.Fprintf(os.Stderr, "lanclip: send to %s: %v\n", addr, err)
			continue
		}
		sent++
		fmt.Fprintf(os.Stderr, "sent to %s\n", addr)
	}
	if sent == 0 {
		os.Exit(1)
	}
}

func runServe(groupKey []byte, deviceID string) {
	saveDir := filepath.Join(configDir(), "received")
	if err := os.MkdirAll(saveDir, 0o755); err != nil {
		fatal(err)
	}

	port := protocol.DefaultPort
	if p := os.Getenv("LANCLIP_PORT"); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}

	pin, _ := crypto.DerivePINBytes(groupKey)
	fmt.Printf("lanclip %s serving as %q (platform=%s, port=%d)\n", appVersion, deviceName(), runtime.GOOS, port)
	fmt.Printf("pairing PIN (must match on both devices): %s\n", pin)

	e, err := transfer.NewEngine(transfer.Config{
		DeviceID:     deviceID,
		DeviceName:   deviceName(),
		Platform:     runtime.GOOS,
		Version:      appVersion,
		GroupKey:     groupKey,
		SaveDir:      saveDir,
		InsecureOpen: os.Getenv("LANCLIP_INSECURE_OPEN") == "1",
		OnClipboardText: func(text, from string) {
			if clipboard.WriteText(text) {
				fmt.Printf("收到文本 from %s: %.80q\n", from, text)
			}
		},
		OnClipboardImage: func(png []byte, from string) {
			if clipboard.WriteImage(png) {
				fmt.Printf("收到图片 from %s: %.1f KB -> 已写入剪贴板\n", from, float64(len(png))/1024)
				return
			}
			// fallback for platforms without clipboard write (e.g. headless
			// linux): keep the screenshot on disk so it is not lost
			name := filepath.Join(saveDir, fmt.Sprintf("clipboard-%d.png", time.Now().UnixMilli()))
			if err := os.WriteFile(name, png, 0o644); err == nil {
				fmt.Printf("收到图片 from %s: %.1f KB -> 无法写剪贴板，已保存 %s\n", from, float64(len(png))/1024, name)
			}
		},
		OnFilesSaved: func(paths []string, from string) {
			fmt.Printf("收到文件 from %s: %v\n", from, paths)
		},
		Logger: func(f string, a ...any) {
			fmt.Printf("[debug] "+f+"\n", a...)
		},
	})
	if err != nil {
		fatal(err)
	}

	plain, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		fatal(err)
	}
	tlsLn := plain // engine wraps each accepted conn with TLS itself (e.Listen)

	ann, err := discovery.Announce(deviceID, deviceName()+"-"+deviceID[:6], runtime.GOOS, appVersion, port)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mDNS announce failed (LANCLIP_PEERS can compensate):", err)
	}
	defer func() { ann.Close() }()

	browser := discovery.NewBrowser()
	defer browser.Stop()

	stopWatch := make(chan struct{})
	startWatcher(e, func() []discovery.Peer { return filterOutSelf(staticAndDiscovered(browser), deviceID) }, stopWatch)

	if apiPort := os.Getenv("LANCLIP_API_PORT"); apiPort != "" {
		go serveAPI(e, apiPort, browser, deviceID)
	}

	go func() {
		if err := e.Listen(tlsLn); err != nil {
			fmt.Fprintln(os.Stderr, "listen:", err)
			os.Exit(1)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	if traySupported() && os.Getenv("LANCLIP_NO_TRAY") != "1" {
		// tray must own the main goroutine on macOS; serve keeps running in
		// its goroutines and Ctrl-C still exits via the signal shim below
		go func() {
			<-sig
			close(stopWatch)
			os.Exit(0)
		}()
		fmt.Println("tray: 菜单栏/托盘已启动（LANCLIP_NO_TRAY=1 可关闭）")
		runTray(e, func() []discovery.Peer {
			return filterOutSelf(staticAndDiscovered(browser), deviceID)
		}, &paused)
		close(stopWatch)
		return
	}

	<-sig
	close(stopWatch)
}

// serveAPI runs the local HTTP API (for phone clients, shortcuts, smoke tests).
func serveAPI(e *transfer.Engine, port string, b *discovery.Browser, selfID string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/peers", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(filterOutSelf(staticAndDiscovered(b), selfID))
	})
	mux.HandleFunc("/api/send-text", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Text string `json:"text"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&req); err != nil || req.Text == "" {
			http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
			return
		}
		sent := 0
		for _, p := range filterOutSelf(staticAndDiscovered(b), selfID) {
			if err := e.SendText(p.Addr, req.Text); err == nil {
				sent++
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]int{"sent": sent})
	})
	mux.HandleFunc("/api/shot", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			PNGBase64 string `json:"png_base64"`
			Name      string `json:"name"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 40<<20)).Decode(&req); err != nil {
			http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
			return
		}
		png, err := base64.StdEncoding.DecodeString(req.PNGBase64)
		if err != nil || len(png) == 0 {
			http.Error(w, `{"error":"bad png_base64"}`, http.StatusBadRequest)
			return
		}
		sent := 0
		for _, p := range filterOutSelf(staticAndDiscovered(b), selfID) {
			if err := e.SendImage(p.Addr, png); err == nil {
				sent++
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]int{"sent": sent})
	})
	fmt.Printf("local API listening on 127.0.0.1:%s (/api/peers, /api/send-text, /api/shot)\n", port)
	if err := http.ListenAndServe("127.0.0.1:"+port, mux); err != nil {
		fmt.Fprintln(os.Stderr, "api:", err)
	}
}

func filterOutSelf(peers []discovery.Peer, selfID string) []discovery.Peer {
	out := peers[:0]
	for _, p := range peers {
		if p.DeviceID != selfID {
			out = append(out, p)
		}
	}
	return out
}

// pushClipboard mirrors WeType's MultiCopy flow: on local clipboard change,
// push text inline (capped), images as streamed refs, copied files as a
// manifest batch — to every known peer.
func pushClipboard(e *transfer.Engine, peers func() []discovery.Peer, u clipboard.Update) {
	if paused.Load() {
		return
	}
	ps := peers()
	if len(ps) == 0 {
		return
	}
	if len(u.Files) > 0 {
		for _, p := range ps {
			if err := e.SendFiles(p.Addr, u.Files); err != nil {
				fmt.Fprintf(os.Stderr, "send files to %s: %v\n", p.DeviceName, err)
			}
		}
		fmt.Printf("[-> files] %d file(s) to %d peer(s)\n", len(u.Files), len(ps))
		return
	}
	if u.Text != "" {
		const maxInline = 1 << 20 // 1MB inline text cap; larger content should be sent as a file
		if len(u.Text) > maxInline {
			fmt.Printf("[skip] text over 1MB inline cap (%d bytes)\n", len(u.Text))
			return
		}
		for _, p := range ps {
			if err := e.SendText(p.Addr, u.Text); err != nil {
				fmt.Fprintf(os.Stderr, "send text to %s: %v\n", p.DeviceName, err)
			}
		}
		fmt.Printf("[-> clipboard] %.80q to %d peer(s)\n", u.Text, len(ps))
		return
	}
	if len(u.PNGData) > 0 {
		for _, p := range ps {
			if err := e.SendImage(p.Addr, u.PNGData); err != nil {
				fmt.Fprintf(os.Stderr, "send image to %s: %v\n", p.DeviceName, err)
			}
		}
		fmt.Printf("[-> image] %.1f KB to %d peer(s)\n", float64(len(u.PNGData))/1024, len(ps))
	}
}

// hashUpdate feeds the watcher content dedupe (suppress echo loops where our
// own pasteboard write races back through the poller).
func hashUpdate(u clipboard.Update) uint64 {
	h := sha256.New()
	h.Write([]byte(u.Text))
	h.Write(u.PNGData)
	for _, f := range u.Files {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	sum := h.Sum(nil)
	v := uint64(0)
	for _, b := range sum[:8] {
		v = v<<8 | uint64(b)
	}
	return v
}
