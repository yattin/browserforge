//go:build !windows

package common

import "os/exec"

func HideCmdWindow(_ *exec.Cmd) {}
