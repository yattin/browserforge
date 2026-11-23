//go:build windows

package common

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

const dpapiPrefix = "dpapi:"

var (
	modCrypt32          = syscall.NewLazyDLL("crypt32.dll")
	procCryptProtect    = modCrypt32.NewProc("CryptProtectData")
	procCryptUnprotect  = modCrypt32.NewProc("CryptUnprotectData")
	modKernel32         = syscall.NewLazyDLL("kernel32.dll")
	procLocalFree       = modKernel32.NewProc("LocalFree")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func makeBlob(b []byte) dataBlob {
	if len(b) == 0 {
		return dataBlob{}
	}
	return dataBlob{
		cbData: uint32(len(b)),
		pbData: &b[0],
	}
}

func blobBytes(blob dataBlob) []byte {
	if blob.cbData == 0 || blob.pbData == nil {
		return nil
	}
	src := unsafe.Slice(blob.pbData, blob.cbData)
	out := make([]byte, len(src))
	copy(out, src)
	return out
}

// ProtectSecret encrypts plaintext using Windows DPAPI (CurrentUser scope).
func ProtectSecret(dataDir, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	in := makeBlob([]byte(plaintext))
	var out dataBlob
	const cryptProtectUIForbidden = 0x1
	r1, _, err := procCryptProtect.Call(
		uintptr(unsafe.Pointer(&in)),
		0,
		0,
		0,
		0,
		uintptr(cryptProtectUIForbidden),
		uintptr(unsafe.Pointer(&out)),
	)
	if r1 == 0 {
		return "", fmt.Errorf("CryptProtectData failed: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	return dpapiPrefix + base64.StdEncoding.EncodeToString(blobBytes(out)), nil
}

// UnprotectSecret decrypts a DPAPI-protected string.
func UnprotectSecret(dataDir, encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	if !strings.HasPrefix(encoded, dpapiPrefix) {
		return "", errors.New("unsupported secret format (expected dpapi: prefix)")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(encoded, dpapiPrefix))
	if err != nil {
		return "", fmt.Errorf("decode secret base64: %w", err)
	}
	in := makeBlob(raw)
	var out dataBlob
	const cryptProtectUIForbidden = 0x1
	r1, _, err := procCryptUnprotect.Call(
		uintptr(unsafe.Pointer(&in)),
		0,
		0,
		0,
		0,
		uintptr(cryptProtectUIForbidden),
		uintptr(unsafe.Pointer(&out)),
	)
	if r1 == 0 {
		return "", fmt.Errorf("CryptUnprotectData failed: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	return string(blobBytes(out)), nil
}
