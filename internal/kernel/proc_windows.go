//go:build windows

package kernel

import (
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"
)

var (
	modKernel32Proc        = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess        = modKernel32Proc.NewProc("OpenProcess")
	procGetExitCodeProcess = modKernel32Proc.NewProc("GetExitCodeProcess")
	procCloseHandle        = modKernel32Proc.NewProc("CloseHandle")
)

const (
	processQueryLimitedInformation = 0x1000
	stillActive                    = 259
)

// IsProcessAlive checks whether pid is running using Win32 syscalls (zero subprocess / zero console flash).
func IsProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, _, _ := procOpenProcess.Call(uintptr(processQueryLimitedInformation), 0, uintptr(uint32(pid)))
	if h == 0 {
		return false
	}
	defer procCloseHandle.Call(h)
	var code uint32
	r1, _, _ := procGetExitCodeProcess.Call(h, uintptr(unsafe.Pointer(&code)))
	if r1 == 0 {
		return false
	}
	return code == stillActive
}

// TerminateProcess terminates a process tree cleanly without flashing a console window.
func TerminateProcess(pid int) error {
	if pid <= 0 {
		return nil
	}
	cmd := exec.Command("taskkill", "/PID", strconv.Itoa(pid), "/T", "/F")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil && IsProcessAlive(pid) {
		return err
	}
	return nil
}
