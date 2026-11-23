//go:build windows

package common

import (
	"os/exec"
	"syscall"
)

// HideCmdWindow prevents console window flashes when GUI processes spawn helper commands on Windows.
func HideCmdWindow(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
}
