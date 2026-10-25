package transfer

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lhg-projects/lhg-lanclip/internal/crypto"
	"github.com/lhg-projects/lhg-lanclip/internal/protocol"
)

func TestSanitizeFileName(t *testing.T) {
	cases := map[string]string{
		"normal.txt":             "normal.txt",
		"../../etc/passwd":       "passwd",
		"..\\..\\evil.sh":        "evil.sh",
		"/absolute/path/x.png":   "x.png",
		"..":                     "unnamed-file",
		".":                      "unnamed-file",
		"":                       "unnamed-file",
		"a\x00b":                 "unnamed-file",
		strings.Repeat("a", 500): "long-name",
	}
	for in, wantPrefix := range cases {
		got := SanitizeFileName(in)
		switch wantPrefix {
		case "unnamed-file":
			if got != "unnamed-file" {
				t.Fatalf("sanitize(%q) = %q, want unnamed-file", in, got)
			}
		case "long-name":
			if len(got) > 200 {
				t.Fatalf("sanitize(%q) too long: %d", in, len(got))
			}
		default:
			if got != wantPrefix {
				t.Fatalf("sanitize(%q) = %q, want %q", in, got, wantPrefix)
			}
		}
		// the result must always be a single safe path element
		if got != filepath.Base(got) || got == ".." {
			t.Fatalf("sanitize(%q) = %q escapes SaveDir", in, got)
		}
	}
}

// newTestEngine spins an engine on an ephemeral port and returns its address.
func newTestEngine(t *testing.T, groupKey []byte) (*Engine, string, string) {
	t.Helper()
	return newTestEngineWithLog(t, groupKey, t.Logf)
}

func newTestEngineWithLog(t *testing.T, groupKey []byte, logger func(string, ...any)) (*Engine, string, string) {
	t.Helper()
	dir := t.TempDir()
	e, err := NewEngine(Config{
		DeviceID:   "server-device",
		DeviceName: "server",
		Platform:   "test",
		Version:    "0.3.0",
		GroupKey:   groupKey,
		SaveDir:    dir,
		Logger:     logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go e.Listen(ln) //nolint:errcheck
	t.Cleanup(func() { ln.Close() })
	return e, ln.Addr().String(), dir
}

// rawClient dials TLS and returns the tls.Conn speaking the wire protocol.
func rawClient(t *testing.T, addr string) *tls.Conn {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true, // mirrors lanclip peers; auth is the hello HMAC
		MinVersion:         tls.VersionTLS13,
		ServerName:         "lanclip_test",
	})
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func exporterOf(t *testing.T, c *tls.Conn) []byte {
	t.Helper()
	st := c.ConnectionState()
	b, err := st.ExportKeyingMaterial(crypto.ExporterLabel, nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sendEnvelope(w *bufio.Writer, typ protocol.MsgType, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	env, err := json.Marshal(struct {
		Type protocol.MsgType `json:"type"`
		Body json.RawMessage  `json:"body"`
	}{typ, b})
	if err != nil {
		return err
	}
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(env)))
	if _, err := w.Write(lb[:]); err != nil {
		return err
	}
	if _, err := w.Write(env); err != nil {
		return err
	}
	return w.Flush()
}

func readEnvelope(r io.Reader) (protocol.MsgType, json.RawMessage, error) {
	var lb [4]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return "", nil, err
	}
	buf := make([]byte, binary.BigEndian.Uint32(lb[:]))
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", nil, err
	}
	var env struct {
		Type protocol.MsgType `json:"type"`
		Body json.RawMessage  `json:"body"`
	}
	if err := json.Unmarshal(buf, &env); err != nil {
		return "", nil, err
	}
	return env.Type, env.Body, nil
}

// TestHelloRejectsStaticTag verifies the hello MAC must be bound to the TLS
// session: a tag computed WITHOUT the exporter (the old static formula, e.g.
// relayed by a MITM over its own connection) must be rejected.
func TestHelloRejectsStaticTag(t *testing.T) {
	key, _ := crypto.NewGroupKey()
	_, addr, _ := newTestEngine(t, key)

	c := rawClient(t, addr)
	rw := bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))

	static := crypto.HelloTag(key, "attacker-device", nil) // no exporter binding
	if err := sendEnvelope(rw.Writer, protocol.MsgHello, protocol.Hello{
		DeviceID: "attacker-device", DeviceName: "attacker", AuthTag: static,
	}); err != nil {
		t.Fatal(err)
	}
	typ, _, err := readEnvelope(rw.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if typ != protocol.MsgError {
		t.Fatalf("expected error frame for static tag, got %q", typ)
	}
}

// TestHelloAcceptsChannelBoundTag is the happy path.
func TestHelloAcceptsChannelBoundTag(t *testing.T) {
	key, _ := crypto.NewGroupKey()
	_, addr, _ := newTestEngine(t, key)

	c := rawClient(t, addr)
	rw := bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))

	exp := exporterOf(t, c)
	if err := sendEnvelope(rw.Writer, protocol.MsgHello, protocol.Hello{
		DeviceID: "buddy", DeviceName: "buddy", Platform: "test",
		AuthTag: crypto.HelloTag(key, "buddy", exp),
	}); err != nil {
		t.Fatal(err)
	}
	typ, _, err := readEnvelope(rw.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if typ != protocol.MsgHelloOK {
		t.Fatalf("expected hello_ok, got %q", typ)
	}
}

// TestManifestPathTraversal verifies a hostile manifest cannot write outside
// SaveDir: "../../pwned.txt" must land as a sanitized name inside the dir.
func TestManifestPathTraversal(t *testing.T) {
	key, _ := crypto.NewGroupKey()
	_, addr, saveDir := newTestEngine(t, key)

	c := rawClient(t, addr)
	rw := bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
	exp := exporterOf(t, c)
	if err := sendEnvelope(rw.Writer, protocol.MsgHello, protocol.Hello{
		DeviceID: "evil", DeviceName: "evil", AuthTag: crypto.HelloTag(key, "evil", exp),
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readEnvelope(rw.Reader); err != nil {
		t.Fatal(err)
	}

	content := []byte("pwned?")
	sum := sha256.Sum256(content)
	if err := sendEnvelope(rw.Writer, protocol.MsgManifest, protocol.Manifest{
		DeviceID: "evil",
		Files: []protocol.FileEntry{{
			FileID: "f1", Name: "../../pwned.txt", Size: int64(len(content)),
			SHA256: hex.EncodeToString(sum[:]),
		}},
	}); err != nil {
		t.Fatal(err)
	}
	// stream the one chunk
	sendChunkRaw(t, rw.Writer, "f1", 0, content)

	// wait for the file to land
	deadline := time.Now().Add(3 * time.Second)
	var inside string
	for time.Now().Before(deadline) {
		entries, _ := os.ReadDir(saveDir)
		for _, en := range entries {
			if en.Name() == "pwned.txt" {
				inside = filepath.Join(saveDir, en.Name())
			}
		}
		if inside != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if inside == "" {
		t.Fatalf("sanitized file never landed in %s", saveDir)
	}
	// the traversal target must NOT exist
	if _, err := os.Stat(filepath.Join(saveDir, "..", "pwned.txt")); !os.IsNotExist(err) {
		t.Fatalf("path traversal escaped SaveDir!")
	}
}

func sendChunkRaw(t *testing.T, w *bufio.Writer, fileID string, offset int64, data []byte) {
	t.Helper()
	sum := sha256.Sum256(data)
	var hash [32]byte
	copy(hash[:], sum[:])
	hdr := protocol.EncodeChunkHeader(fileID, offset, len(data), hash)
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(hdr)))
	w.Write(lb[:])
	w.Write(hdr)
	w.Write(data)
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
}

// TestRecvChunkRejectsOversizeLength feeds a chunk header declaring a giant
// payload; the server must abort instead of allocating gigabytes.
func TestRecvChunkRejectsOversizeLength(t *testing.T) {
	key, _ := crypto.NewGroupKey()
	_, addr, _ := newTestEngine(t, key)

	c := rawClient(t, addr)
	rw := bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
	exp := exporterOf(t, c)
	if err := sendEnvelope(rw.Writer, protocol.MsgHello, protocol.Hello{
		DeviceID: "evil2", DeviceName: "evil2", AuthTag: crypto.HelloTag(key, "evil2", exp),
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readEnvelope(rw.Reader); err != nil {
		t.Fatal(err)
	}
	// announce a small image, then lie about the chunk data length
	if err := sendEnvelope(rw.Writer, protocol.MsgImageRef, protocol.ImageRef{
		DeviceID: "evil2", Version: uint64(time.Now().UnixNano()), FileID: "x",
		Name: "x.png", Size: 1024, SHA256: "",
	}); err != nil {
		t.Fatal(err)
	}
	// chunk header declaring 0x7FFFFFFF bytes of payload
	var hash [32]byte
	hdr := protocol.EncodeChunkHeader("x", 0, 0x7FFFFFFF, hash)
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(hdr)))
	rw.Writer.Write(lb[:])
	rw.Writer.Write(hdr)
	if err := rw.Writer.Flush(); err != nil {
		t.Fatal(err)
	}
	// server must close the connection (error out), not allocate
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	if _, err := rw.Reader.Read(buf); err == nil {
		t.Fatal("server kept the connection open after oversized chunk header")
	}
}

func TestAckProtocolVersions(t *testing.T) {
	cases := map[string]bool{
		"0.3.0": true, "0.4.1": true, "1.0.0": true,
		"0.2.0": false, "0.1.0": false, "test": false, "": false,
	}
	for v, want := range cases {
		if got := AckProtocol(v); got != want {
			t.Fatalf("AckProtocol(%q) = %v, want %v", v, got, want)
		}
	}
}

// TestFileTransferResume pre-seeds a .partial with the first chunk, re-sends
// the whole file, and asserts the sender resumed from the offset and the
// completed file hashes correctly.
func TestFileTransferResume(t *testing.T) {
	key, _ := crypto.NewGroupKey()
	var mu sync.Mutex
	var logbuf []string
	logger := func(f string, a ...any) {
		mu.Lock()
		logbuf = append(logbuf, fmt.Sprintf(f, a...))
		mu.Unlock()
	}
	_, addr, dir := newTestEngineWithLog(t, key, logger)

	payload := make([]byte, int(float64(protocol.ChunkSize)*2.5))
	for i := range payload {
		payload[i] = byte(i)
	}
	src := filepath.Join(t.TempDir(), "resume.bin")
	if err := os.WriteFile(src, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "resume.bin")
	if err := os.WriteFile(dst+".partial", payload[:protocol.ChunkSize], 0o644); err != nil {
		t.Fatal(err)
	}

	sender, err := NewEngine(Config{
		DeviceID: "sender-dev", DeviceName: "sender", Platform: "test",
		Version: "0.3.0", GroupKey: key, SaveDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.SendFiles(addr, []string{src}); err != nil {
		t.Fatalf("SendFiles: %v", err)
	}

	// the receiver finishes asynchronously; poll for the completed file
	deadline := time.Now().Add(5 * time.Second)
	var got []byte
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(dst)
		if err == nil {
			got = b
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got == nil {
		mu.Lock()
		t.Fatalf("resumed file never appeared; server logs:\n%s", strings.Join(logbuf, "\n"))
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("resumed file mismatch: %d bytes", len(got))
	}
	if _, err := os.Stat(dst + ".partial"); !os.IsNotExist(err) {
		t.Fatalf(".partial still present after success")
	}
	// and both sides must report the resume path
	mu.Lock()
	defer mu.Unlock()
	joined := strings.Join(logbuf, "\n")
	if !strings.Contains(joined, "resuming resume.bin at 262144") {
		t.Fatalf("no receiver resume log; got:\n%s", joined)
	}
}

// TestFileTransferResumeCorruptPrefix ensures a mismatched final hash wipes
// the bad .partial so the next attempt can succeed instead of failing forever.
func TestFileTransferResumeCorruptPrefix(t *testing.T) {
	key, _ := crypto.NewGroupKey()
	_, addr, dir := newTestEngineWithLog(t, key, t.Logf)

	payload := bytes.Repeat([]byte{7}, protocol.ChunkSize*2)
	src := filepath.Join(t.TempDir(), "corrupt.bin")
	os.WriteFile(src, payload, 0o644)
	dst := filepath.Join(dir, "corrupt.bin")
	// poisoned prefix: right LENGTH but wrong bytes
	bad := bytes.Repeat([]byte{9}, protocol.ChunkSize)
	os.WriteFile(dst+".partial", bad, 0o644)

	sender, _ := NewEngine(Config{
		DeviceID: "sender-dev", DeviceName: "sender", Platform: "test",
		Version: "0.3.0", GroupKey: key, SaveDir: t.TempDir(),
	})
	// push is one-way: SendFiles succeeding does not mean the receiver
	// accepted the content; what matters is what the receiver did with it
	if err := sender.SendFiles(addr, []string{src}); err != nil {
		t.Fatalf("SendFiles: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, perr := os.Stat(dst + ".partial")
		_, derr := os.Stat(dst)
		if os.IsNotExist(perr) && os.IsNotExist(derr) {
			return // poisoned prefix wiped, no bad file delivered
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("corrupt .partial not removed (or bad dst created) after hash mismatch")
}
