//go:build windows

package kernel

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modVersion                 = syscall.NewLazyDLL("version.dll")
	procGetFileVersionInfoSize = modVersion.NewProc("GetFileVersionInfoSizeW")
	procGetFileVersionInfo     = modVersion.NewProc("GetFileVersionInfoW")
	procVerQueryValue          = modVersion.NewProc("VerQueryValueW")
)

type vsFixedFileInfo struct {
	Signature        uint32
	StrucVersion     uint32
	FileVersionMS    uint32
	FileVersionLS    uint32
	ProductVersionMS uint32
	ProductVersionLS uint32
	FileFlagsMask    uint32
	FileFlags        uint32
	FileOS           uint32
	FileType         uint32
	FileSubtype      uint32
	FileDateMS       uint32
	FileDateLS       uint32
}

// ReadExecutableVersion extracts the PE FileVersion (major.minor.build.rev) on Windows.
func ReadExecutableVersion(exePath string) string {
	p, err := syscall.UTF16PtrFromString(exePath)
	if err != nil {
		return ""
	}
	var handle uint32
	size, _, _ := procGetFileVersionInfoSize.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&handle)))
	if size == 0 {
		return ""
	}
	buf := make([]byte, size)
	r1, _, _ := procGetFileVersionInfo.Call(
		uintptr(unsafe.Pointer(p)),
		0,
		size,
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if r1 == 0 {
		return ""
	}
	root, _ := syscall.UTF16PtrFromString(`\`)
	var fi *vsFixedFileInfo
	var infoLen uint32
	r2, _, _ := procVerQueryValue.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(root)),
		uintptr(unsafe.Pointer(&fi)),
		uintptr(unsafe.Pointer(&infoLen)),
	)
	if r2 == 0 || fi == nil || infoLen < uint32(unsafe.Sizeof(vsFixedFileInfo{})) {
		return ""
	}
	major := fi.FileVersionMS >> 16
	minor := fi.FileVersionMS & 0xffff
	build := fi.FileVersionLS >> 16
	rev := fi.FileVersionLS & 0xffff
	if major == 0 && minor == 0 && build == 0 && rev == 0 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", major, minor, build, rev)
}
