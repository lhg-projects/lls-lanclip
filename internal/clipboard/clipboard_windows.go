//go:build windows

// Package clipboard watches and writes the Windows clipboard via user32
// (AddClipboardFormatListener + GetClipboardData), the Windows counterpart of
// WeType's ClipboardMonitor. Text uses CF_UNICODETEXT; images convert to and
// from CF_DIBV5 (32bpp BGRA / 24bpp BGR); copied Explorer files surface as
// CF_HDROP path lists (Update.Files) and auto-sync as file transfers.
package clipboard

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"strings"
	"syscall"
	"unsafe"
)

var (
	user32           = syscall.NewLazyDLL("user32.dll")
	procOpenClip     = user32.NewProc("OpenClipboard")
	procCloseClip    = user32.NewProc("CloseClipboard")
	procEmptyClip    = user32.NewProc("EmptyClipboard")
	procGetClipData  = user32.NewProc("GetClipboardData")
	procSetClipData  = user32.NewProc("SetClipboardData")
	procIsFmtAvail   = user32.NewProc("IsClipboardFormatAvailable")
	procAddListener  = user32.NewProc("AddClipboardFormatListener")
	procGetMessageW  = user32.NewProc("GetMessageW")
	procCreateWindow = user32.NewProc("CreateWindowExW")
	procDefWindow    = user32.NewProc("DefWindowProcW")
	procRegisterCls  = user32.NewProc("RegisterClassExW")
	shell32          = syscall.NewLazyDLL("shell32.dll")
	procDragQuery    = shell32.NewProc("DragQueryFileW")
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procGlobalAlloc  = kernel32.NewProc("GlobalAlloc")
	procGlobalLock   = kernel32.NewProc("GlobalLock")
	procGlobalUnlock = kernel32.NewProc("GlobalUnlock")
	procGlobalSize   = kernel32.NewProc("GlobalSize")
)

const (
	cfUnicodeText = 13
	cfHDrop       = 15
	cfDIBV5       = 17
	gmemMoveable  = 0x0002
	wmClipboard   = 0x0308

	biRGB       = 0
	biBitfields = 3
)

// Update is one observed clipboard change.
type Update struct {
	Text    string
	PNGData []byte
	Files   []string // local file paths when files were copied (CF_HDROP)
}

// readText pulls CF_UNICODETEXT with the allocation size as the hard bound
// (scanning a fixed window past the allocation would read out of bounds).
func readText() (string, bool) {
	h, _, _ := procGetClipData.Call(cfUnicodeText)
	if h == 0 {
		return "", false
	}
	size, _, _ := procGlobalSize.Call(h)
	if size < 2 {
		return "", false
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		return "", false
	}
	defer procGlobalUnlock.Call(h)
	raw := unsafe.Slice((*uint16)(unsafe.Pointer(p)), size/2)
	n := 0
	for raw[n] != 0 && n < len(raw)-1 {
		n++
	}
	return syscall.UTF16ToString(raw[:n]), true
}

// readDropFiles lists paths from a CF_HDROP handle.
func readDropFiles(h uintptr) []string {
	n, _, _ := procDragQuery.Call(h, 0xFFFFFFFF, 0, 0)
	if n == 0 {
		return nil
	}
	var out []string
	for i := uintptr(0); i < n; i++ {
		ln, _, _ := procDragQuery.Call(h, i, 0, 0)
		if ln == 0 {
			continue
		}
		buf := make([]uint16, ln+1)
		procDragQuery.Call(h, i, uintptr(unsafe.Pointer(&buf[0])), ln+1) //nolint:gosec
		out = append(out, syscall.UTF16ToString(buf))
	}
	return out
}

// readImage converts CF_DIBV5 to PNG for the sync protocol.
func readImage() ([]byte, error) {
	h, _, _ := procGetClipData.Call(cfDIBV5)
	if h == 0 {
		return nil, fmt.Errorf("no CF_DIBV5 on clipboard")
	}
	size, _, _ := procGlobalSize.Call(h)
	if size < 124 {
		return nil, fmt.Errorf("DIBV5 too small (%d bytes)", size)
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		return nil, fmt.Errorf("GlobalLock failed")
	}
	defer procGlobalUnlock.Call(h)

	dib := unsafe.Slice((*byte)(unsafe.Pointer(p)), size)
	width := int(int32(binary.LittleEndian.Uint32(dib[4:8])))
	height := int(int32(binary.LittleEndian.Uint32(dib[8:12])))
	bpp := int(binary.LittleEndian.Uint16(dib[14:16]))
	compression := binary.LittleEndian.Uint32(dib[16:20])
	if width <= 0 || height == 0 {
		return nil, fmt.Errorf("bad DIB dimensions %dx%d", width, height)
	}
	bottomUp := height > 0
	if bottomUp {
		height = -height
	}

	var rM, gM, bM, aM uint32
	switch compression {
	case biRGB:
		rM, gM, bM, aM = 0xFF0000, 0xFF00, 0xFF, 0
	case biBitfields:
		rM = binary.LittleEndian.Uint32(dib[40:44])
		gM = binary.LittleEndian.Uint32(dib[44:48])
		bM = binary.LittleEndian.Uint32(dib[48:52])
		aM = binary.LittleEndian.Uint32(dib[52:56])
	default:
		return nil, fmt.Errorf("unsupported DIB compression %d", compression)
	}

	stride := ((width*bpp + 31) / 32) * 4
	px := dib[124:]
	if len(px) < stride*height {
		return nil, fmt.Errorf("DIB pixel data truncated")
	}

	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		srcY := y
		if bottomUp {
			srcY = height - 1 - y
		}
		row := px[srcY*stride : srcY*stride+stride]
		for x := 0; x < width; x++ {
			switch bpp {
			case 32:
				px32 := binary.LittleEndian.Uint32(row[x*4:])
				img.SetNRGBA(x, y, maskedNRGBA(px32, rM, gM, bM, aM))
			case 24:
				b, g, r := row[x*3], row[x*3+1], row[x*3+2]
				img.SetNRGBA(x, y, color.NRGBA{R: r, G: g, B: b, A: 255})
			default:
				return nil, fmt.Errorf("unsupported DIB bit depth %d", bpp)
			}
		}
	}
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func maskShift(m uint32) (shift uint8, used bool) {
	if m == 0 {
		return 0, false
	}
	s := uint8(0)
	for m&1 == 0 {
		m >>= 1
		s++
	}
	return s, true
}

func maskedNRGBA(v, rM, gM, bM, aM uint32) color.NRGBA {
	var c color.NRGBA
	if s, ok := maskShift(rM); ok {
		c.R = scale8((v & rM) >> s)
	}
	if s, ok := maskShift(gM); ok {
		c.G = scale8((v & gM) >> s)
	}
	if s, ok := maskShift(bM); ok {
		c.B = scale8((v & bM) >> s)
	}
	if s, ok := maskShift(aM); ok {
		c.A = scale8((v & aM) >> s)
	} else {
		c.A = 255
	}
	return c
}

// scale8 rescales a channel of arbitrary mask width to 8 bits.
func scale8(v uint32) uint8 {
	switch {
	case v <= 0xFF:
		return uint8(v)
	case v <= 0xFFFF:
		return uint8(v >> 8)
	default:
		return uint8(v >> 16)
	}
}

// read returns the current clipboard contents (files first, then text, then
// image: Explorer copies advertise both file names and text, files win).
func read() (Update, bool) {
	if r, _, _ := procIsFmtAvail.Call(cfHDrop); r != 0 {
		if h, _, _ := procGetClipData.Call(cfHDrop); h != 0 {
			if files := readDropFiles(h); len(files) > 0 {
				return Update{Files: files}, true
			}
		}
	}
	if r, _, _ := procIsFmtAvail.Call(cfUnicodeText); r != 0 {
		if text, ok := readText(); ok && text != "" {
			return Update{Text: text}, true
		}
	}
	if r, _, _ := procIsFmtAvail.Call(cfDIBV5); r != 0 {
		if pngBytes, err := readImage(); err == nil {
			return Update{PNGData: pngBytes}, true
		}
	}
	return Update{}, false
}

// ---------- watcher ----------

// Watcher runs a hidden message window receiving WM_CLIPBOARDUPDATE.
type Watcher struct {
	hwnd     uintptr
	callback func(Update)
	lastText string
	lastImg  string
	lastFls  string
}

type wndClassEx struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

var windows = map[uintptr]*Watcher{}

func wndProcThunk(hwnd, msg, wp, lp uintptr) uintptr {
	if msg == wmClipboard {
		if w := windows[hwnd]; w != nil {
			go w.onChange() // don't block the window pump on conversions
		}
	}
	r, _, _ := procDefWindow.Call(hwnd, msg, wp, lp)
	return r
}

// NewWatcher creates the listener window and starts pumping messages.
func NewWatcher(cb func(Update)) (*Watcher, error) {
	className, _ := syscall.UTF16PtrFromString("LanClipWatcher")
	cls := wndClassEx{
		CbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		LpfnWndProc:   syscall.NewCallback(wndProcThunk),
		LpszClassName: className,
	}
	wcAtom, _, err := procRegisterCls.Call(uintptr(unsafe.Pointer(&cls)))
	if wcAtom == 0 {
		return nil, fmt.Errorf("RegisterClassExW: %v", err)
	}
	w := &Watcher{callback: cb}
	hwnd, _, err := procCreateWindow.Call(0, uintptr(unsafe.Pointer(className)), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	if hwnd == 0 {
		return nil, fmt.Errorf("CreateWindowExW: %v", err)
	}
	w.hwnd = hwnd
	windows[hwnd] = w
	if r, _, err := procAddListener.Call(hwnd); r == 0 {
		return nil, fmt.Errorf("AddClipboardFormatListener: %v", err)
	}
	go w.pump()
	return w, nil
}

func (w *Watcher) onChange() {
	u, ok := read()
	if !ok {
		return
	}
	if u.Text != "" {
		if u.Text == w.lastText {
			return
		}
		w.lastText = u.Text
	}
	if len(u.PNGData) > 0 {
		h := fmt.Sprintf("%x", len(u.PNGData)) // cheap dedupe; sync layer hashes too
		if h == w.lastImg {
			return
		}
		w.lastImg = h
	}
	if len(u.Files) > 0 {
		sig := strings.Join(u.Files, "\x00")
		if sig == w.lastFls {
			return
		}
		w.lastFls = sig
	}
	w.callback(u)
}

func (w *Watcher) pump() {
	var msg [48]byte // MSG
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg[0])), 0, 0, 0)
		if r == 0 || int64(r) == -1 {
			return
		}
	}
}

// Poll is a no-op on Windows (the watcher is push-based); kept for API parity.
func Poll() (Update, bool) { return Update{}, false }

// WriteText replaces the clipboard text.
func WriteText(s string) bool {
	if r, _, _ := procOpenClip.Call(0); r == 0 {
		return false
	}
	defer procCloseClip.Call()
	procEmptyClip.Call()
	u16, err := syscall.UTF16FromString(s)
	if err != nil {
		return false
	}
	size := len(u16) * 2
	h, _, _ := procGlobalAlloc.Call(gmemMoveable, uintptr(size))
	if h == 0 {
		return false
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		return false
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(p)), size), u16Bytes(u16))
	procGlobalUnlock.Call(h)
	r, _, _ := procSetClipData.Call(cfUnicodeText, h)
	return r != 0
}

func u16Bytes(u []uint16) []byte {
	out := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(out[i*2:], v)
	}
	return out
}

// WriteImage converts PNG bytes to a bottom-up 32bpp BI_BITFIELDS CF_DIBV5
// and places it on the clipboard.
func WriteImage(pngBytes []byte) bool {
	if len(pngBytes) == 0 {
		return false
	}
	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		return false
	}
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()

	const hdrSize = 124
	stride := w * 4
	total := hdrSize + stride*h
	hg, _, _ := procGlobalAlloc.Call(gmemMoveable, uintptr(total))
	if hg == 0 {
		return false
	}
	p, _, _ := procGlobalLock.Call(hg)
	if p == 0 {
		return false
	}
	dib := unsafe.Slice((*byte)(unsafe.Pointer(p)), total)

	le := binary.LittleEndian
	// BITMAPV5HEADER
	le.PutUint32(dib[0:4], hdrSize)
	le.PutUint32(dib[4:8], uint32(w))
	le.PutUint32(dib[8:12], uint32(h)) // positive => bottom-up
	le.PutUint16(dib[12:14], 1)        // planes
	le.PutUint16(dib[14:16], 32)       // bpp
	le.PutUint32(dib[16:20], biBitfields)
	le.PutUint32(dib[20:24], uint32(stride*h))
	le.PutUint32(dib[40:44], 0xFF0000) // red mask
	le.PutUint32(dib[44:48], 0xFF00)   // green mask
	le.PutUint32(dib[48:52], 0xFF)     // blue mask
	le.PutUint32(dib[52:56], 0xFF000000)
	le.PutUint32(dib[56:60], 0x73524742) // 'sRGB'

	for y := 0; y < h; y++ {
		dstY := h - 1 - y // flip to bottom-up
		row := dib[hdrSize+dstY*stride:]
		for x := 0; x < w; x++ {
			r, g, b, a := img.At(b.Min.X+x, b.Min.Y+y).RGBA()
			row[x*4+0] = byte(b >> 8)
			row[x*4+1] = byte(g >> 8)
			row[x*4+2] = byte(r >> 8)
			row[x*4+3] = byte(a >> 8)
		}
	}
	procGlobalUnlock.Call(hg)

	if r, _, _ := procOpenClip.Call(0); r == 0 {
		return false
	}
	defer procCloseClip.Call()
	procEmptyClip.Call()
	rv, _, _ := procSetClipData.Call(cfDIBV5, hg)
	return rv != 0
}
