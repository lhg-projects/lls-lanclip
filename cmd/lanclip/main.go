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
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/lhg-projects/lhg-lanclip/internal/api"
	"github.com/lhg-projects/lhg-lanclip/internal/clipboard"
	"github.com/lhg-projects/lhg-lanclip/internal/crypto"
	"github.com/lhg-projects/lhg-lanclip/internal/discovery"
	"github.com/lhg-projects/lhg-lanclip/internal/pair"
	"github.com/lhg-projects/lhg-lanclip/internal/protocol"
	"github.com/lhg-projects/lhg-lanclip/internal/settings"
	"github.com/lhg-projects/lhg-lanclip/internal/transfer"
)

const appVersion = "0.5.0"

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
	// Double-clicked .app bundle: no args + running from Contents/MacOS ->
	// become the background sync daemon (menu bar) and log to a file instead
	// of a terminal that does not exist.
	if len(os.Args) == 1 {
		if exe, err := os.Executable(); err == nil && strings.Contains(exe, ".app/Contents/MacOS/") {
			runAppBundleMode()
			return
		}
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
		to, rest := pickTo(os.Args[2:])
		if len(rest) == 0 {
			fatal(fmt.Errorf("usage: lanclip send-text [--to 设备名/IP] TEXT"))
		}
		text := strings.Join(rest, " ")
		sendToPeers(key, deviceID, to, func(addr string, e *transfer.Engine) error {
			return e.SendText(addr, text)
		})
	case "send-file":
		to, rest := pickTo(os.Args[2:])
		if len(rest) == 0 {
			fatal(fmt.Errorf("usage: lanclip send-file [--to 设备名/IP] PATH [PATH...]"))
		}
		sendToPeers(key, deviceID, to, func(addr string, e *transfer.Engine) error {
			return e.SendFiles(addr, rest)
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

// runAppBundleMode redirects stdout/stderr into the config dir and serves.
func runAppBundleMode() {
	dir := configDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fatal(err)
	}
	logPath := filepath.Join(dir, "lanclip.log")
	if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		// fmt.Printf reads os.Stdout at call time, so reassigning the vars
		// redirects all daemon logging into the file (no syscall needed,
		// portable across darwin/windows/linux)
		os.Stdout = f
		os.Stderr = f
	}
	fmt.Printf("=== lanclip app mode, %s ===\n", time.Now().Format(time.RFC3339))
	key, err := loadOrCreateGroupKey()
	if err != nil {
		fatal(err)
	}
	deviceID := loadOrCreateDeviceID()
	if guiSupported() && os.Getenv("LANCLIP_NO_GUI") != "1" {
		_, serr := os.Stat(filepath.Join(configDir(), "settings.json"))
		firstRun := os.IsNotExist(serr)
		srv := startServe(key, deviceID)
		runGUI(srv, firstRun) // blocks the main goroutine (GUI runloop)
		srv.cleanup()
		return
	}
	runServe(key, deviceID)
}

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

// pickTo extracts an optional --to/-t target from args.
func pickTo(args []string) (to string, rest []string) {
	rest = args
	if len(rest) >= 2 && (rest[0] == "--to" || rest[0] == "-t") {
		return rest[1], rest[2:]
	}
	return "", rest
}

// sendToPeers resolves peers (static first, else mDNS), optionally narrowed
// by name/id/addr substring, and runs fn on each desktop peer; android peers
// are routed through the HTTP face instead.
func sendToPeers(groupKey []byte, deviceID, to string, fn func(addr string, e *transfer.Engine) error) {
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
	if to != "" {
		// narrow by name/id/addr substring
		var narrow []string
		for _, a := range targets {
			if strings.Contains(a, to) {
				narrow = append(narrow, a)
			}
		}
		targets = narrow
	}
	if len(targets) == 0 {
		fatal(fmt.Errorf("no peer matches %q (see `lanclip peers`)", to))
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

// serveStack bundles the running daemon's handles for UI/tray consumers.
type serveStack struct {
	engine    *transfer.Engine
	browser   *discovery.Browser
	settings  *settings.Store
	groupKey  []byte
	deviceID  string
	peersFunc func() []discovery.Peer
	stopWatch chan struct{}
	cleanup   func()
	// setEngineHook installs the inbox feed (see startServe's hookBox).
	setEngineHook func(fn func(kind, from, text, name string, size int64, fileURL string))
}

// startServe brings up everything except the main-thread loop (tray/GUI/
// signal wait): engine, TLS listener, mDNS announce/browse, clipboard
// watcher, optional HTTP API. Call cleanup() on shutdown.
func startServe(groupKey []byte, deviceID string) *serveStack {
	st, err := settings.Load(configDir(), filepath.Join(configDir(), "received"), deviceName())
	if err != nil {
		fatal(err)
	}
	cur := st.Get()
	syncPrefs.mu.Lock()
	syncPrefs.text, syncPrefs.images, syncPrefs.files = cur.SyncText, cur.SyncImages, cur.SyncFiles
	syncPrefs.mu.Unlock()
	saveDir := cur.SaveDir
	if saveDir == "" {
		saveDir = filepath.Join(configDir(), "received")
	}
	if err := os.MkdirAll(saveDir, 0o755); err != nil {
		fatal(err)
	}

	port := protocol.DefaultPort
	if p := os.Getenv("LANCLIP_PORT"); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}

	pin, _ := crypto.DerivePINBytes(groupKey)
	fmt.Printf("lanclip %s serving as %q (platform=%s, port=%d)\n", appVersion, cur.DeviceName, runtime.GOOS, port)
	fmt.Printf("pairing PIN (must match on both devices): %s\n", pin)

	// hookBox feeds received items into the API inbox once serveAPI runs
	hookBox := &struct {
		fn func(kind, from, text, name string, size int64, fileURL string)
	}{}
	e, err := transfer.NewEngine(transfer.Config{
		DeviceID:     deviceID,
		DeviceName:   cur.DeviceName,
		Platform:     runtime.GOOS,
		Version:      appVersion,
		GroupKey:     groupKey,
		SaveDir:      saveDir,
		InsecureOpen: os.Getenv("LANCLIP_INSECURE_OPEN") == "1",
		OnClipboardText: func(text, from string) {
			if clipboard.WriteText(text) {
				fmt.Printf("收到文本 from %s: %.80q\n", from, text)
			}
			if hookBox.fn != nil {
				hookBox.fn("text", from, text, "", 0, "")
			}
		},
		OnClipboardImage: func(png []byte, from string) {
			if hookBox.fn != nil {
				hookBox.fn("image", from, "", "clipboard.png", int64(len(png)), "")
			}
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
			if hookBox.fn != nil {
				for _, p := range paths {
					if st, err := os.Stat(p); err == nil {
						hookBox.fn("file", from, "", filepath.Base(p), st.Size(), "")
					}
				}
			}
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
	go func() {
		if err := e.Listen(plain); err != nil { // engine wraps TLS per conn
			fmt.Fprintln(os.Stderr, "listen:", err)
			os.Exit(1)
		}
	}()

	annName := cur.DeviceName + "-" + deviceID[:6]
	ann, err := discovery.Announce(deviceID, annName, runtime.GOOS, appVersion, port)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mDNS announce failed (LANCLIP_PEERS can compensate):", err)
	}

	browser := discovery.NewBrowser()
	stopWatch := make(chan struct{})
	srv := &serveStack{
		engine:   e,
		browser:  browser,
		settings: st,
		groupKey: groupKey,
		deviceID: deviceID,
		setEngineHook: func(fn func(kind, from, text, name string, size int64, fileURL string)) {
			hookBox.fn = fn
		},
		peersFunc: func() []discovery.Peer { return filterOutSelf(staticAndDiscovered(browser), deviceID) },
		stopWatch: stopWatch,
		cleanup: func() {
			close(stopWatch)
			browser.Stop()
			if ann != nil {
				ann.Close()
			}
			plain.Close()
		},
	}
	startWatcher(srv, srv.peersFunc, stopWatch)
	startShotWatcher(srv, srv.peersFunc, stopWatch)

	if apiPort := os.Getenv("LANCLIP_API_PORT"); apiPort != "" {
		go serveAPI(srv, apiPort)
	}
	return srv
}

// runServe is the CLI daemon entry: background stack + tray or signal wait.
func runServe(groupKey []byte, deviceID string) {
	srv := startServe(groupKey, deviceID)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	if traySupported() && os.Getenv("LANCLIP_NO_TRAY") != "1" {
		// tray must own the main goroutine on macOS; serve keeps running in
		// its goroutines and Ctrl-C still exits via the signal shim below
		go func() {
			<-sig
			srv.cleanup()
			os.Exit(0)
		}()
		fmt.Println("tray: 菜单栏/托盘已启动（LANCLIP_NO_TRAY=1 可关闭）")
		runTray(srv, &paused)
		srv.cleanup()
		return
	}

	<-sig
	srv.cleanup()
}

// apiRouter builds the authenticated LAN HTTP face: phones (no TLS exporter
// in JSSE, no background clipboard) talk to these endpoints with the group
// key; loopback callers stay exempt for local tooling and smoke tests.
func apiRouter(srv *serveStack) (http.Handler, *api.Inbox) {
	inbox := api.NewInbox(200)
	e, b, selfID := srv.engine, srv.browser, srv.deviceID

	srv.setEngineHook(func(kind, from, text, name string, size int64, fileURL string) {
		inbox.Add(kind, from, text, name, size, fileURL)
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/api/ping", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"app": "lanclip", "version": appVersion})
	})
	mux.HandleFunc("/api/peers", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(srv.peersFunc())
	})
	mux.HandleFunc("/api/inbox", func(w http.ResponseWriter, r *http.Request) {
		since := int64(0)
		if v := r.URL.Query().Get("since"); v != "" {
			fmt.Sscanf(v, "%d", &since)
		}
		_ = json.NewEncoder(w).Encode(inbox.Since(since))
	})

	targets := func(to string) []discovery.Peer {
		ps := srv.peersFunc()
		if to == "" {
			return ps
		}
		lto := strings.ToLower(to)
		var out []discovery.Peer
		for _, p := range ps {
			if p.DeviceID == to || strings.HasPrefix(p.DeviceID, to) ||
				p.Addr == to || strings.Contains(p.Addr, to) ||
				strings.Contains(strings.ToLower(p.DeviceName), lto) {
				out = append(out, p)
			}
		}
		return out
	}

	mux.HandleFunc("/api/send-text", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Text string `json:"text"`
			To   string `json:"to"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&req); err != nil || req.Text == "" {
			http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sent": sendTextTo(srv, targets(req.To), req.Text)})
	})
	mux.HandleFunc("/api/shot", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			PNGBase64 string `json:"png_base64"`
			Name      string `json:"name"`
			To        string `json:"to"`
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
		_ = json.NewEncoder(w).Encode(map[string]any{"sent": sendImageTo(srv, targets(req.To), png)})
	})
	mux.HandleFunc("/api/send-file", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			http.Error(w, `{"error":"bad multipart"}`, http.StatusBadRequest)
			return
		}
		to := r.FormValue("to")
		fh := r.MultipartForm.File["file"]
		if len(fh) == 0 {
			http.Error(w, `{"error":"missing file"}`, http.StatusBadRequest)
			return
		}
		f, err := fh[0].Open()
		if err != nil {
			http.Error(w, `{"error":"bad file part"}`, http.StatusBadRequest)
			return
		}
		defer f.Close()
		tmp, err := os.CreateTemp("", "lanclip-upload-*")
		if err != nil {
			http.Error(w, `{"error":"tmp"}`, http.StatusInternalServerError)
			return
		}
		if _, err := io.Copy(tmp, f); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			http.Error(w, `{"error":"read"}`, http.StatusBadRequest)
			return
		}
		tmp.Close()
		defer os.Remove(tmp.Name())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sent": sendFileTo(srv, targets(to), fh[0].Filename, tmp.Name()),
		})
	})
	_ = e
	_ = b
	_ = selfID
	return api.NewVerifier(srv.groupKey).Middleware(mux), inbox
}

// serveAPI runs the LAN HTTP face. LANCLIP_API_BIND=lan (or =IP) opens it to
// the network; default stays loopback-only.
func serveAPI(srv *serveStack, port string) {
	handler, _ := apiRouter(srv)
	bind := "127.0.0.1"
	switch v := os.Getenv("LANCLIP_API_BIND"); v {
	case "lan", "0.0.0.0":
		bind = "0.0.0.0"
	case "":
	default:
		bind = v
	}
	fmt.Printf("api: http://%s:%s (/api/ping /api/peers /api/send-text /api/shot /api/send-file /api/inbox)\n", bind, port)
	if err := http.ListenAndServe(bind+":"+port, handler); err != nil {
		fmt.Fprintln(os.Stderr, "api:", err)
	}
}

// sendTextTo routes per-peer: desktop peers use the binary TLS protocol,
// Android peers (mDNS platform=android) get HMAC-authed HTTP.
func sendTextTo(srv *serveStack, ps []discovery.Peer, text string) int {
	sent := 0
	for _, p := range ps {
		var err error
		if p.Platform == "android" {
			err = api.NewClient("http://"+p.Addr, srv.groupKey).SendText(text)
		} else {
			err = srv.engine.SendText(p.Addr, text)
		}
		if err == nil {
			sent++
		} else {
			fmt.Fprintf(os.Stderr, "send text to %s(%s): %v\n", p.DeviceName, p.Platform, err)
		}
	}
	return sent
}

func sendImageTo(srv *serveStack, ps []discovery.Peer, png []byte) int {
	sent := 0
	for _, p := range ps {
		var err error
		if p.Platform == "android" {
			err = api.NewClient("http://"+p.Addr, srv.groupKey).SendImage(base64.StdEncoding.EncodeToString(png))
		} else {
			err = srv.engine.SendImage(p.Addr, png)
		}
		if err == nil {
			sent++
		} else {
			fmt.Fprintf(os.Stderr, "send image to %s(%s): %v\n", p.DeviceName, p.Platform, err)
		}
	}
	return sent
}

func sendFileTo(srv *serveStack, ps []discovery.Peer, name, path string) int {
	sent := 0
	for _, p := range ps {
		var err error
		if p.Platform == "android" {
			content, rerr := os.ReadFile(path)
			if rerr == nil {
				err = api.NewClient("http://"+p.Addr, srv.groupKey).SendFile(name, content)
			} else {
				err = rerr
			}
		} else {
			sendPath := path
			if base := filepath.Base(path); base != name && name != "" {
				// preserve the caller-supplied name (e.g. API uploads) by
				// staging a hardlink/copy with the right basename
				if d, derr := os.MkdirTemp("", "lanclip-name-*"); derr == nil {
					staged := filepath.Join(d, transfer.SanitizeFileName(name))
					if cerr := copyFile(staged, path); cerr == nil {
						sendPath = staged
						defer os.RemoveAll(d)
					} else {
						os.RemoveAll(d)
					}
				}
			}
			err = srv.engine.SendFiles(p.Addr, []string{sendPath})
		}
		if err == nil {
			sent++
		} else {
			fmt.Fprintf(os.Stderr, "send file to %s(%s): %v\n", p.DeviceName, p.Platform, err)
		}
	}
	return sent
}

func copyFile(dst, src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
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
// syncPrefs mirrors the settings store for the hot path (updated by the GUI).
var syncPrefs struct {
	mu                  sync.RWMutex
	text, images, files bool
}

func syncEnabled(kind string) bool {
	syncPrefs.mu.RLock()
	defer syncPrefs.mu.RUnlock()
	switch kind {
	case "text":
		return syncPrefs.text
	case "images":
		return syncPrefs.images
	default:
		return syncPrefs.files
	}
}

func pushClipboard(srv *serveStack, peers func() []discovery.Peer, u clipboard.Update) {
	if paused.Load() {
		return
	}
	ps := peers()
	if len(ps) == 0 {
		return
	}
	if len(u.Files) > 0 {
		if !syncEnabled("files") {
			return
		}
		n := 0
		for _, f := range u.Files {
			n += sendFileTo(srv, ps, filepath.Base(f), f)
		}
		fmt.Printf("[-> files] %d file(s) to %d peer(s)\n", n, len(ps))
		return
	}
	if u.Text != "" {
		if !syncEnabled("text") {
			return
		}
		const maxInline = 1 << 20 // 1MB inline text cap; larger content should be sent as a file
		if len(u.Text) > maxInline {
			fmt.Printf("[skip] text over 1MB inline cap (%d bytes)\n", len(u.Text))
			return
		}
		n := sendTextTo(srv, ps, u.Text)
		fmt.Printf("[-> clipboard] %.80q to %d peer(s)\n", u.Text, n)
		return
	}
	if len(u.PNGData) > 0 {
		if !syncEnabled("images") {
			return
		}
		n := sendImageTo(srv, ps, u.PNGData)
		fmt.Printf("[-> image] %.1f KB to %d peer(s)\n", float64(len(u.PNGData))/1024, n)
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
