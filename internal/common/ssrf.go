package common

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
)

// ErrSSRFBlocked is returned when a dial attempt targets a disallowed loopback/link-local/private IP.
var ErrSSRFBlocked = errors.New("blocked by SSRF protection")

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// IsBlockedIP reports whether ip falls into loopback, unspecified, link-local (IMDS), or private LAN ranges.
func IsBlockedIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsPrivate() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateTargetHost checks a literal IP host (or hostname) against SSRF rules when allowLocal is false.
func ValidateTargetHost(host string, allowLocal bool) error {
	clean := strings.TrimSpace(host)
	if clean == "" {
		return fmt.Errorf("%w: empty host", ErrSSRFBlocked)
	}
	for _, r := range clean {
		if r <= 0x20 || r == 0x7f {
			return fmt.Errorf("%w: invalid control/whitespace character in host", ErrSSRFBlocked)
		}
	}
	if allowLocal {
		return nil
	}
	lower := strings.TrimSuffix(strings.ToLower(clean), ".")
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") ||
		lower == "metadata" || lower == "metadata.google.internal" ||
		strings.HasSuffix(lower, ".internal") || strings.HasSuffix(lower, ".local") ||
		strings.HasSuffix(lower, ".home.arpa") {
		return fmt.Errorf("%w: %s", ErrSSRFBlocked, host)
	}
	trimmedIP := strings.Trim(lower, "[]")
	if addr, err := netip.ParseAddr(trimmedIP); err == nil {
		if IsBlockedIP(addr) {
			return fmt.Errorf("%w: %s", ErrSSRFBlocked, addr)
		}
	}
	return nil
}

// SafeDialerControl returns a net.Dialer.Control callback that blocks SSRF targets post-DNS resolution.
func SafeDialerControl(allowLocal bool) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		if allowLocal {
			return nil
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("%w: invalid address %q", ErrSSRFBlocked, address)
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return fmt.Errorf("%w: non-IP resolved address %q", ErrSSRFBlocked, host)
		}
		if IsBlockedIP(addr) {
			return fmt.Errorf("%w: %s", ErrSSRFBlocked, addr)
		}
		return nil
	}
}
