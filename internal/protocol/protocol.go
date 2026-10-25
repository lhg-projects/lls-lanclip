// Package protocol defines the wire format between lanclip peers.
//
// Design notes (informed by reverse-engineering WeType's DeviceSync/FileTransfer
// stack, see REVERSE-ENGINEERING-REPORT.md):
//   - every message is a length-prefixed JSON frame (4-byte big-endian length);
//   - clipboard entries carry a monotonic version + device_id so receivers can
//     drop echo/stale updates (WeType: "ignore clipboard echoed from current
//     device" / "ignore duplicate or stale clipboard");
//   - file payloads never travel through these frames: the manifest announces
//     files, then each file streams in fixed-size chunks (per-chunk sha256,
//     strictly sequential offsets, whole-file sha256 at the end), so memory
//     stays flat regardless of file size.
package protocol

import "encoding/binary"

const (
	// MaxFrameSize caps one JSON frame (metadata only, never file bytes).
	MaxFrameSize = 4 << 20 // 4 MiB

	// ChunkSize is the streaming unit for file payloads.
	ChunkSize = 256 << 10 // 256 KiB

	// MaxInlineImage caps clipboard images, which buffer in memory on the
	// receiving side (files stream to disk and have no such cap). WeType
	// caps clipboard images at 100MB for its cloud path; on a LAN 32MB is
	// already far beyond any real screenshot.
	MaxInlineImage = 32 << 20 // 32 MiB

	// MaxChunkAckBacklog bounds unacked chunks in flight.
	MaxChunkAckBacklog = 8

	// ServiceName is the mDNS service type ("_lanclip._tcp").
	ServiceName = "lanclip"

	// DefaultPort is the fallback TCP port recorded in TXT-less discovery.
	DefaultPort = 47717
)

// MsgType discriminates frames.
type MsgType string

const (
	// MsgHello is the first frame after TLS handshake: identity + pairing pin hash.
	MsgHello MsgType = "hello"
	// MsgHelloOK confirms accepted identity.
	MsgHelloOK MsgType = "hello_ok"
	// MsgClipboard carries a text clipboard update (inline, size-capped).
	MsgClipboard MsgType = "clipboard"
	// MsgImageRef carries an image clipboard as a pending file reference
	// (receiver pulls it on the same connection; avoids pasting megabytes
	// into the system clipboard writer).
	MsgImageRef MsgType = "image_ref"
	// MsgManifest announces files about to be sent.
	MsgManifest MsgType = "manifest"
	// MsgChunkData is a raw file chunk (outside JSON framing: header + bytes).
	MsgChunkData MsgType = "chunk_data"
	// MsgChunkAck acknowledges one chunk by offset.
	MsgChunkAck MsgType = "chunk_ack"
	// MsgFileDone confirms a whole file (with sha256).
	MsgFileDone MsgType = "file_done"
	// MsgError aborts the session with a reason.
	MsgError MsgType = "error"
)

// Hello is the identity frame.
type Hello struct {
	DeviceID   string `json:"device_id"` // stable random UUID
	DeviceName string `json:"device_name"`
	Platform   string `json:"platform"` // darwin / windows / linux
	Version    string `json:"version"`
	AuthTag    string `json:"auth_tag"` // hex(HMAC-SHA256(groupKey, "lanclip-hello-v1"))
}

// Clipboard is a text clipboard update.
type Clipboard struct {
	DeviceID string `json:"device_id"`
	Version  uint64 `json:"version"`
	Text     string `json:"text"`
	TS       int64  `json:"ts"` // unix millis, informational
}

// ImageRef points at an image streamed as a pseudo-file right after this frame.
type ImageRef struct {
	DeviceID string `json:"device_id"`
	Version  uint64 `json:"version"`
	FileID   string `json:"file_id"`
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	Width    int    `json:"width,omitempty"`
	Height   int    `json:"height,omitempty"`
}

// FileEntry describes one file inside a manifest.
type FileEntry struct {
	FileID  string `json:"file_id"`
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	IsImage bool   `json:"is_image,omitempty"` // image goes to clipboard, not save dir
}

// Manifest announces the file batch about to stream.
type Manifest struct {
	DeviceID string      `json:"device_id"`
	Files    []FileEntry `json:"files"`
}

// ChunkHeader precedes raw chunk bytes on the wire (binary, not JSON).
type ChunkHeader struct {
	FileID   string
	Offset   int64
	Length   int
	DataHash [32]byte // sha256 of the chunk, checked before writing
}

// EncodeChunkHeader packs the fixed-size binary chunk header.
func EncodeChunkHeader(fileID string, offset int64, length int, hash [32]byte) []byte {
	buf := make([]byte, 0, 36+len(fileID))
	var idbuf [8]byte
	copy(idbuf[:], "LCPCHV01")
	buf = append(buf, idbuf[:]...)
	var fb [4]byte
	binary.BigEndian.PutUint32(fb[:], uint32(len(fileID)))
	buf = append(buf, fb[:]...)
	buf = append(buf, fileID...)
	var off [8]byte
	binary.BigEndian.PutUint64(off[:], uint64(offset))
	buf = append(buf, off[:]...)
	var ln [4]byte
	binary.BigEndian.PutUint32(ln[:], uint32(length))
	buf = append(buf, ln[:]...)
	buf = append(buf, hash[:]...)
	return buf
}

// DecodeChunkHeader is the inverse of EncodeChunkHeader.
func DecodeChunkHeader(b []byte) (fileID string, offset int64, length int, hash [32]byte, err error) {
	if len(b) < 16 || string(b[:8]) != "LCPCHV01" {
		err = ErrBadHeader
		return
	}
	idLen := int(binary.BigEndian.Uint32(b[8:12]))
	p := 12
	if len(b) < p+idLen+12+32 {
		err = ErrBadHeader
		return
	}
	fileID = string(b[p : p+idLen])
	p += idLen
	offset = int64(binary.BigEndian.Uint64(b[p:]))
	p += 8
	length = int(binary.BigEndian.Uint32(b[p:]))
	p += 4
	copy(hash[:], b[p:p+32])
	return
}

// Framing errors.
var (
	ErrBadHeader     = errStr("bad chunk header")
	ErrFrameTooLarge = errStr("frame exceeds MaxFrameSize")
)

type errStr string

func (e errStr) Error() string { return string(e) }
