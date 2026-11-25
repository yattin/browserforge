//go:build windows

package main

import (
	_ "embed"
	"encoding/binary"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"browserforge/internal/daemon"
)

//go:embed browserforge.ico
var embeddedIconICO []byte

var (
	modUser32   = syscall.NewLazyDLL("user32.dll")
	modShell32  = syscall.NewLazyDLL("shell32.dll")
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")
	modGdi32    = syscall.NewLazyDLL("gdi32.dll")

	procGetModuleHandleW        = modKernel32.NewProc("GetModuleHandleW")
	procRegisterClassExW        = modUser32.NewProc("RegisterClassExW")
	procCreateWindowExW         = modUser32.NewProc("CreateWindowExW")
	procDefWindowProcW          = modUser32.NewProc("DefWindowProcW")
	procDestroyWindow           = modUser32.NewProc("DestroyWindow")
	procGetMessageW             = modUser32.NewProc("GetMessageW")
	procTranslateMessage        = modUser32.NewProc("TranslateMessage")
	procDispatchMessageW        = modUser32.NewProc("DispatchMessageW")
	procPostQuitMessage         = modUser32.NewProc("PostQuitMessage")
	procPostMessageW            = modUser32.NewProc("PostMessageW")
	procRegisterWindowMessageW  = modUser32.NewProc("RegisterWindowMessageW")
	procLoadIconW               = modUser32.NewProc("LoadIconW")
	procCreateIconFromResourceEx = modUser32.NewProc("CreateIconFromResourceEx")
	procCreateIconIndirect      = modUser32.NewProc("CreateIconIndirect")
	procDestroyIcon             = modUser32.NewProc("DestroyIcon")
	procCreatePopupMenu         = modUser32.NewProc("CreatePopupMenu")
	procAppendMenuW             = modUser32.NewProc("AppendMenuW")
	procTrackPopupMenu          = modUser32.NewProc("TrackPopupMenu")
	procDestroyMenu             = modUser32.NewProc("DestroyMenu")
	procGetCursorPos            = modUser32.NewProc("GetCursorPos")
	procSetForegroundWindow     = modUser32.NewProc("SetForegroundWindow")
	procMessageBoxW             = modUser32.NewProc("MessageBoxW")
	procShellNotifyIconW        = modShell32.NewProc("Shell_NotifyIconW")
	procShellExecuteW           = modShell32.NewProc("ShellExecuteW")
	procCreateBitmap            = modGdi32.NewProc("CreateBitmap")
	procDeleteObject            = modGdi32.NewProc("DeleteObject")
)

const (
	wmNull           = 0x0000
	wmDestroy        = 0x0002
	wmCommand        = 0x0111
	wmUser           = 0x0400
	wmTrayCallback   = wmUser + 1
	wmLButtonDblClk  = 0x0203
	wmRButtonUp      = 0x0205
	wmContextMenu    = 0x007B

	nimAdd    = 0x00000000
	nimModify = 0x00000001
	nimDelete = 0x00000002

	nifMessage = 0x00000001
	nifIcon    = 0x00000002
	nifTip     = 0x00000004
	nifInfo    = 0x00000010
	niifInfo   = 0x00000001

	mfString    = 0x00000000
	mfGrayed    = 0x00000001
	mfDisabled  = 0x00000002
	mfSeparator = 0x00000800

	tpmRightAlign   = 0x0008
	tpmBottomAlign  = 0x0020
	tpmReturnCmd    = 0x0100
	tpmNonotify     = 0x0080

	idiApplication = 32512
	mbOK           = 0x00000000
	mbIconInfo     = 0x00000040
	swShowNormal   = 1

	cmdOpenPanel   = 1001
	cmdOpenDataDir = 1002
	cmdStopAll     = 1003
	cmdExit        = 1004
)

type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

type point struct {
	X int32
	Y int32
}

type msg struct {
	HWnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}

type notifyIconDataW struct {
	cbSize           uint32
	hWnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            uintptr
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         [16]byte
	hBalloonIcon     uintptr
}

type iconInfo struct {
	fIcon    int32
	xHotspot uint32
	yHotspot uint32
	hbmMask  uintptr
	hbmColor uintptr
}

var (
	traySrv             *daemon.Server
	trayDataDir         string
	trayHwnd            uintptr
	trayIconHandle      uintptr
	wmTaskbarCreatedMsg uint32
)

func copyUTF16(dst []uint16, s string) {
	u, err := syscall.UTF16FromString(s)
	if err != nil {
		return
	}
	n := copy(dst, u)
	if n > 0 && n == len(dst) {
		dst[len(dst)-1] = 0
	}
}

// loadEmbeddedTrayIcon parses the embedded multi-size ICO and creates a crisp 32x32 RGBA HICON.
func loadEmbeddedTrayIcon(ico []byte) uintptr {
	if len(ico) < 22 {
		return 0
	}
	count := int(binary.LittleEndian.Uint16(ico[4:6]))
	if count <= 0 || len(ico) < 6+count*16 {
		return 0
	}
	// Pick the 32x32 entry (or closest >= 32, fallback to first entry)
	bestOff, bestLen, bestDiff := 0, 0, 999999
	for i := 0; i < count; i++ {
		base := 6 + i*16
		w := int(ico[base])
		if w == 0 {
			w = 256
		}
		size := int(binary.LittleEndian.Uint32(ico[base+8 : base+12]))
		off := int(binary.LittleEndian.Uint32(ico[base+12 : base+16]))
		if off < 0 || size <= 0 || off+size > len(ico) {
			continue
		}
		diff := w - 32
		if diff < 0 {
			diff = -diff + 100 // prefer >= 32 over upscaling smaller
		}
		if diff < bestDiff {
			bestDiff = diff
			bestOff = off
			bestLen = size
		}
	}
	if bestLen <= 0 {
		return 0
	}
	frame := ico[bestOff : bestOff+bestLen]
	// LR_DEFAULTCOLOR = 0x0000, dwVer = 0x00030000
	hIcon, _, _ := procCreateIconFromResourceEx.Call(
		uintptr(unsafe.Pointer(&frame[0])),
		uintptr(len(frame)),
		1,          // fIcon = TRUE
		0x00030000, // dwVer
		32,         // cxDesired
		32,         // cyDesired
		0,          // Flags
	)
	return hIcon
}

// buildBrandIcon creates a crisp 32x32 tray HICON from the embedded brand ICO (with GDI fallback).
func buildBrandIcon() uintptr {
	if h := loadEmbeddedTrayIcon(embeddedIconICO); h != 0 {
		return h
	}
	const size = 32
	pixels := make([]byte, size*size*4) // BGRA
	mask := make([]byte, (size/8)*size) // 1-bit AND mask (all 0 = opaque where alpha>0)

	// 5x7 pixel bitmap for uppercase "B" (scaled 2x -> 10x14 centered in 32x32)
	glyphB := []string{
		"11110",
		"10001",
		"10001",
		"11110",
		"10001",
		"10001",
		"11110",
	}

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			// Rounded square SDF
			cx := float64(x) - 15.5
			cy := float64(y) - 15.5
			ax := cx
			if ax < 0 {
				ax = -ax
			}
			ay := cy
			if ay < 0 {
				ay = -ay
			}
			inside := true
			if ax > 10.5 && ay > 10.5 {
				dx := ax - 10.5
				dy := ay - 10.5
				if dx*dx+dy*dy > 4.5*4.5 {
					inside = false
				}
			} else if ax > 15.0 || ay > 15.0 {
				inside = false
			}

			idx := (y*size + x) * 4
			if !inside {
				// Transparent outside rounded badge
				mask[y*(size/8)+x/8] |= 1 << (7 - uint(x%8))
				continue
			}

			// Check if inside "B" glyph (origin x=11..20, y=9..22)
			gx := (x - 11) / 2
			gy := (y - 9) / 2
			inGlyph := x >= 11 && x < 21 && y >= 9 && y < 23 && glyphB[gy][gx] == '1'

			if inGlyph {
				pixels[idx+0] = 0xFF // B
				pixels[idx+1] = 0xFF // G
				pixels[idx+2] = 0xFF // R
				pixels[idx+3] = 0xFF // A
			} else {
				// Emerald-teal gradient (#10B981 -> #059669)
				pixels[idx+0] = byte(0x81 - (y * 24 / size)) // B
				pixels[idx+1] = byte(0xB9 - (y * 30 / size)) // G
				pixels[idx+2] = byte(0x10 - (y * 10 / size)) // R
				pixels[idx+3] = 0xFF                         // A
			}
		}
	}

	hColor, _, _ := procCreateBitmap.Call(size, size, 1, 32, uintptr(unsafe.Pointer(&pixels[0])))
	hMask, _, _ := procCreateBitmap.Call(size, size, 1, 1, uintptr(unsafe.Pointer(&mask[0])))
	if hColor == 0 || hMask == 0 {
		if hColor != 0 {
			procDeleteObject.Call(hColor)
		}
		if hMask != 0 {
			procDeleteObject.Call(hMask)
		}
		h, _, _ := procLoadIconW.Call(0, idiApplication)
		return h
	}
	ii := iconInfo{fIcon: 1, hbmMask: hMask, hbmColor: hColor}
	hIcon, _, _ := procCreateIconIndirect.Call(uintptr(unsafe.Pointer(&ii)))
	procDeleteObject.Call(hColor)
	procDeleteObject.Call(hMask)
	if hIcon == 0 {
		h, _, _ := procLoadIconW.Call(0, idiApplication)
		return h
	}
	return hIcon
}

func openShellTarget(target string) {
	verb, _ := syscall.UTF16PtrFromString("open")
	tgt, _ := syscall.UTF16PtrFromString(target)
	procShellExecuteW.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(tgt)), 0, 0, swShowNormal)
}

func addTrayIcon(hwnd, hIcon uintptr, st daemon.DaemonState, withBalloon bool) {
	var nid notifyIconDataW
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = hwnd
	nid.uID = 1
	nid.uFlags = nifMessage | nifIcon | nifTip
	nid.uCallbackMessage = wmTrayCallback
	nid.hIcon = hIcon
	copyUTF16(nid.szTip[:], fmt.Sprintf("BrowserForge Daemon v%s (127.0.0.1:%d)", st.Version, st.Port))
	if withBalloon {
		nid.uFlags |= nifInfo
		nid.dwInfoFlags = niifInfo
		copyUTF16(nid.szInfoTitle[:], "BrowserForge Daemon Ready")
		copyUTF16(nid.szInfo[:], fmt.Sprintf("Listening on 127.0.0.1:%d · Double-click to open status panel", st.Port))
	}
	procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))
}

func removeTrayIcon(hwnd uintptr) {
	var nid notifyIconDataW
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = hwnd
	nid.uID = 1
	procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
}

func showContextMenu(hwnd uintptr) {
	hMenu, _, _ := procCreatePopupMenu.Call()
	if hMenu == 0 {
		return
	}
	defer procDestroyMenu.Call(hMenu)

	st := traySrv.State()
	active := traySrv.ActiveBrowserCount()

	appendItem := func(flags uintptr, id uintptr, text string) {
		var p *uint16
		if text != "" {
			p, _ = syscall.UTF16PtrFromString(text)
		}
		procAppendMenuW.Call(hMenu, flags, id, uintptr(unsafe.Pointer(p)))
	}

	appendItem(mfString|mfGrayed|mfDisabled, 0, fmt.Sprintf("BrowserForge v%s (127.0.0.1:%d)", st.Version, st.Port))
	appendItem(mfString|mfGrayed|mfDisabled, 0, fmt.Sprintf("Active Browsers: %d  |  PID: %d", active, st.PID))
	appendItem(mfSeparator, 0, "")
	appendItem(mfString, cmdOpenPanel, "Open Status Panel")
	appendItem(mfString, cmdOpenDataDir, "Open Data Folder")
	appendItem(mfString, cmdStopAll, "Stop All Browsers")
	appendItem(mfSeparator, 0, "")
	appendItem(mfString, cmdExit, "Exit Daemon")

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(hwnd)

	cmd, _, _ := procTrackPopupMenu.Call(
		hMenu,
		tpmRightAlign|tpmBottomAlign|tpmReturnCmd|tpmNonotify,
		uintptr(pt.X),
		uintptr(pt.Y),
		0,
		hwnd,
		0,
	)
	procPostMessageW.Call(hwnd, wmNull, 0, 0)

	switch cmd {
	case cmdOpenPanel:
		if url, err := traySrv.CreatePanelEnterURL(); err == nil {
			openShellTarget(url)
		}
	case cmdOpenDataDir:
		openShellTarget(trayDataDir)
	case cmdStopAll:
		go traySrv.StopAllBrowsers()
	case cmdExit:
		go traySrv.Close()
		procDestroyWindow.Call(hwnd)
	}
}

func trayWndProc(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	if wmTaskbarCreatedMsg != 0 && message == wmTaskbarCreatedMsg {
		addTrayIcon(hwnd, trayIconHandle, traySrv.State(), false)
		return 0
	}
	switch message {
	case wmTrayCallback:
		switch uint32(lParam) {
		case wmLButtonDblClk:
			if url, err := traySrv.CreatePanelEnterURL(); err == nil {
				openShellTarget(url)
			}
		case wmRButtonUp, wmContextMenu:
			showContextMenu(hwnd)
		}
		return 0
	case wmDestroy:
		removeTrayIcon(hwnd)
		procPostQuitMessage.Call(0)
		return 0
	}
	ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(message), wParam, lParam)
	return ret
}

func runTray(srv *daemon.Server, dataDir string) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	traySrv = srv
	trayDataDir = dataDir

	hInst, _, _ := procGetModuleHandleW.Call(0)
	clsName, _ := syscall.UTF16PtrFromString("BrowserForgeDaemonTrayWindow")
	tbMsgName, _ := syscall.UTF16PtrFromString("TaskbarCreated")
	rMsg, _, _ := procRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(tbMsgName)))
	wmTaskbarCreatedMsg = uint32(rMsg)

	trayIconHandle = buildBrandIcon()
	defer func() {
		if trayIconHandle != 0 {
			procDestroyIcon.Call(trayIconHandle)
		}
	}()

	wc := wndClassExW{
		cbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
		lpfnWndProc:   syscall.NewCallback(trayWndProc),
		hInstance:     hInst,
		hIcon:         trayIconHandle,
		lpszClassName: clsName,
	}
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(clsName)),
		uintptr(unsafe.Pointer(clsName)),
		0, 0, 0, 0, 0,
		0, 0, hInst, 0,
	)
	if hwnd == 0 {
		<-srv.Done()
		return
	}
	trayHwnd = hwnd

	addTrayIcon(hwnd, trayIconHandle, srv.State(), true)

	// If daemon is stopped externally (e.g. `browserforge daemon stop`), close tray cleanly.
	go func() {
		<-srv.Done()
		procPostMessageW.Call(hwnd, wmDestroy, 0, 0)
	}()

	var m msg
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func showAlreadyRunningDialog(existing *daemon.DaemonState) {
	// When the user double-clicks the desktop shortcut while the daemon is already running,
	// mint a fresh single-use ticket and open the authenticated BrowserForge status panel directly.
	if existing != nil {
		if panelURL, err := daemon.RequestPanelURL(existing); err == nil && panelURL != "" {
			openShellTarget(panelURL)
			return
		}
	}
	pid := 0
	if existing != nil {
		pid = existing.PID
	}
	title, _ := syscall.UTF16PtrFromString("BrowserForge")
	body, _ := syscall.UTF16PtrFromString(fmt.Sprintf(
		"BrowserForge Daemon is already running (PID: %d).\n\nLook for the BrowserForge icon in your Windows system tray.",
		pid,
	))
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(body)), uintptr(unsafe.Pointer(title)), mbOK|mbIconInfo)
}
