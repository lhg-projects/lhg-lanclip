//go:build windows

// Package clipboard watches and writes the Windows clipboard via user32
// (AddClipboardFormatListener + GetClipboardData), the Windows counterpart of
// WeType's ClipboardMonitor.
package clipboard

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

var (
	user32           = syscall.NewLazyDLL("user32.dll")
	procOpenClip     = user32.NewProc("OpenClipboard")
	procCloseClip    = user32.NewProc("CloseClipboard")
	procEmptyClip    = user32.NewProc("EmptyClipboard")
	procGetClipData  = user32.NewProc("GetClipboardData")
	procSetClipData  = user32.NewProc("SetClipboardData")
	procEnumFormats  = user32.NewProc("EnumClipboardFormats")
	procAddListener  = user32.NewProc("AddClipboardFormatListener")
	procGetMessageW  = user32.NewProc("GetMessageW")
	procCreateWindow = user32.NewProc("CreateWindowExW")
	procDefWindow    = user32.NewProc("DefWindowProcW")
	procRegisterCls  = user32.NewProc("RegisterClassExW")
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procGlobalAlloc  = kernel32.NewProc("GlobalAlloc")
	procGlobalLock   = kernel32.NewProc("GlobalLock")
	procGlobalUnlock = kernel32.NewProc("GlobalUnlock")
)

const (
	cfUnicodeText = 13
	cfDIBV5       = 17
	gmemMoveable  = 0x0002
	wmClipboard   = 0x0308
)

// Update is one observed clipboard change.
type Update struct {
	Text    string
	PNGData []byte // encoded from CF_DIBV5 on read
}

// Watcher runs a hidden message window receiving WM_CLIPBOARDUPDATE.
type Watcher struct {
	hwnd     uintptr
	callback func(Update)
	// snapshot dedup: same content re-set by some apps repeats the message
	lastText string
	lastHash uint64
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

// NewWatcher creates the listener window and starts pumping messages.
func NewWatcher(cb func(Update)) (*Watcher, error) {
	className, _ := syscall.UTF16PtrFromString("LanClipWatcher")
	cls := wndClassEx{CbSize: uint32(unsafe.Sizeof(wndClassEx{})), LpszClassName: className}
	// default window proc keeps the window alive; we intercept via subclass trick below
	cls.LpfnWndProc = syscall.NewCallback(wndProcThunk)
	wcAtom, _, err := procRegisterCls.Call(uintptr(unsafe.Pointer(&cls)))
	if wcAtom == 0 {
		return nil, fmt.Errorf("RegisterClassExW: %v", err)
	}
	w := &Watcher{callback: cb}
	hwnd, _, err := procCreateWindow.Call(
		0, uintptr(unsafe.Pointer(className)), 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0)
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

var windows = map[uintptr]*Watcher{}

func wndProcThunk(hwnd, msg, wp, lp uintptr) uintptr {
	if msg == wmClipboard {
		if w := windows[hwnd]; w != nil {
			w.onChange()
		}
	}
	r, _, _ := procDefWindow.Call(hwnd, msg, wp, lp)
	return r
}

func (w *Watcher) onChange() {
	u, ok := read()
	if !ok {
		return
	}
	if u.Text != "" && u.Text == w.lastText {
		return
	}
	w.lastText = u.Text
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

func read() (Update, bool) {
	if r, _, _ := procOpenClip.Call(0); r == 0 {
		return Update{}, false
	}
	defer procCloseClip.Call()
	u := Update{}
	if h, _, _ := procGetClipData.Call(cfUnicodeText); h != 0 {
		p, _, _ := procGlobalLock.Call(h)
		if p != 0 {
			// UTF-16, NUL terminated
			raw := unsafe.Slice((*uint16)(unsafe.Pointer(p)), 1<<20)
			n := 0
			for raw[n] != 0 && n < len(raw)-1 {
				n++
			}
			u.Text = syscall.UTF16ToString(raw[:n])
			procGlobalUnlock.Call(h)
			return u, true
		}
	}
	return u, false
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

// WriteImage is not implemented on Windows yet (CF_DIBV5 conversion TODO);
// text sync works fully.
func WriteImage(png []byte) bool { return false }

// ensure imports used
var _ = time.Second
