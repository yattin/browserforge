package common

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestProtectAndUnprotectSecret(t *testing.T) {
	dir := t.TempDir()
	secret := "p@ssw0rd!#12345"
	enc, err := ProtectSecret(dir, secret)
	if err != nil {
		t.Fatalf("ProtectSecret: %v", err)
	}
	if enc == "" || enc == secret {
		t.Fatalf("secret was not encrypted: %q", enc)
	}
	dec, err := UnprotectSecret(dir, enc)
	if err != nil {
		t.Fatalf("UnprotectSecret: %v", err)
	}
	if dec != secret {
		t.Fatalf("roundtrip mismatch: got %q, want %q", dec, secret)
	}
}

func TestWriteFileAtomicReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "beryl", "fingerprint.json")
	if err := WriteFileAtomic(path, []byte(`{"ok":true}`), 0o444); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm()&0o222 != 0 {
		t.Fatalf("expected read-only mode, got %v", info.Mode().Perm())
	}
	// Updating a read-only file via WriteFileAtomic must succeed cleanly.
	if err := WriteFileAtomic(path, []byte(`{"ok":2}`), 0o444); err != nil {
		t.Fatalf("WriteFileAtomic overwrite read-only: %v", err)
	}
	_ = SetReadOnly(path, false)
}

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{"127.0.0.1", "0.0.0.0", "169.254.169.254", "10.0.0.5", "192.168.1.1", "172.16.0.1", "::1", "fe80::1"}
	for _, s := range blocked {
		ip := netip.MustParseAddr(s)
		if !IsBlockedIP(ip) {
			t.Fatalf("expected %s to be blocked", s)
		}
	}
	allowed := []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"}
	for _, s := range allowed {
		ip := netip.MustParseAddr(s)
		if IsBlockedIP(ip) {
			t.Fatalf("expected %s to be allowed", s)
		}
	}
}

func TestValidateTargetHostHardened(t *testing.T) {
	for _, bad := range []string{
		"LOCALHOST",
		"sub.localhost.",
		"metadata.google.internal",
		"mybox.local",
		"[::1]",
		"example.com\r\nX-Inject: 1",
		"169.254.169.254",
	} {
		if err := ValidateTargetHost(bad, false); err == nil {
			t.Fatalf("expected host %q to be blocked", bad)
		}
	}
	if err := ValidateTargetHost("example.com", false); err != nil {
		t.Fatalf("expected example.com allowed, got %v", err)
	}
}
