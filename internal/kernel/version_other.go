//go:build !windows

package kernel

import (
	"os/exec"
	"regexp"
)

var verRe = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`)

func ReadExecutableVersion(exePath string) string {
	out, err := exec.Command(exePath, "--version").Output()
	if err != nil {
		return ""
	}
	if m := verRe.FindStringSubmatch(string(out)); len(m) == 2 {
		return m[1]
	}
	return ""
}
