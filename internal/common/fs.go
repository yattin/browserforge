package common

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// EnsurePrivateDir creates dir with 0700 permissions and applies Windows ACL tightening on first creation.
func EnsurePrivateDir(dir string) error {
	_, statErr := os.Stat(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if os.IsNotExist(statErr) {
		_ = RestrictPathACL(dir)
	}
	return nil
}

// WriteFileAtomic writes data via temp file + Sync + Rename, optionally applying read-only mode.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// If destination exists and is read-only on Windows, clear read-only before replacing.
	if _, err := os.Stat(path); err == nil {
		_ = SetReadOnly(path, false)
	}

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, perm); err != nil && runtime.GOOS != "windows" {
		return err
	}
	if err := replaceFileAtomic(tmpPath, path); err != nil {
		return fmt.Errorf("atomic replace %s: %w", path, err)
	}
	cleanup = false
	if perm&0o222 == 0 {
		_ = SetReadOnly(path, true)
	}
	return nil
}

// SetReadOnly locks or unlocks the read-only file attribute.
func SetReadOnly(path string, readonly bool) error {
	if readonly {
		return os.Chmod(path, 0o444)
	}
	return os.Chmod(path, 0o600)
}

// RestrictPathACL narrows filesystem ACLs to the current user (best-effort on Windows via icacls).
func RestrictPathACL(path string) error {
	if runtime.GOOS != "windows" {
		return os.Chmod(path, 0o700)
	}
	user := strings.TrimSpace(os.Getenv("USERNAME"))
	if user == "" {
		return nil
	}
	domain := strings.TrimSpace(os.Getenv("USERDOMAIN"))
	principal := user
	if domain != "" {
		principal = domain + `\` + user
	}
	cmd := exec.Command("icacls", path,
		"/inheritance:r",
		"/grant:r", principal+":(OI)(CI)F",
		"/grant:r", "*S-1-5-18:(OI)(CI)F",
		"/grant:r", "*S-1-5-32-544:(OI)(CI)F",
	)
	HideCmdWindow(cmd)
	_ = cmd.Run()
	return nil
}

// DefaultDataDir returns the default BrowserForge data directory.
func DefaultDataDir() string {
	if v := strings.TrimSpace(os.Getenv("BROWSERFORGE_DATA_DIR")); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		if base := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); base != "" {
			return filepath.Join(base, "BrowserForge")
		}
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".browserforge")
	}
	return filepath.Join(".", ".browserforge-data")
}
