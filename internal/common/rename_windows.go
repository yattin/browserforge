//go:build windows

package common

import (
	"syscall"
	"unsafe"
)

var (
	modKernel32FS   = syscall.NewLazyDLL("kernel32.dll")
	procMoveFileExW = modKernel32FS.NewProc("MoveFileExW")
)

const (
	movefileReplaceExisting = 0x1
	movefileWriteThrough    = 0x8
)

// replaceFileAtomic performs a zero-gap atomic replace on Windows via MoveFileExW.
func replaceFileAtomic(src, dst string) error {
	srcPtr, err := syscall.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	dstPtr, err := syscall.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	r1, _, callErr := procMoveFileExW.Call(
		uintptr(unsafe.Pointer(srcPtr)),
		uintptr(unsafe.Pointer(dstPtr)),
		uintptr(movefileReplaceExisting|movefileWriteThrough),
	)
	if r1 == 0 {
		return callErr
	}
	return nil
}
