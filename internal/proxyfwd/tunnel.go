package proxyfwd

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"browserforge/internal/common"
)

const (
	MaxHandshakeBytes = 64 * 1024 // 64 KiB cap on proxy handshake headers
	MaxProbeBytes     = 1 << 20   // 1 MiB cap on exit-IP probe response
)

// UpstreamConfig defines an upstream proxy server.
type UpstreamConfig struct {
	Scheme             string `json:"scheme"` // http, https, socks5
	Host               string `json:"host"`
	Port               int    `json:"port"`
	Username           string `json:"username,omitempty"`
	Password           string `json:"password,omitempty"`
	AllowLocal         bool   `json:"allow_local,omitempty"`
	AllowLocalUpstream bool   `json:"allow_local_upstream,omitempty"`
	RuntimeFile        string `json:"runtime_file,omitempty"`
}

// DialUpstreamThrough connects to targetAddr ("host:port") through the configured upstream proxy.
func DialUpstreamThrough(ctx context.Context, cfg UpstreamConfig, targetAddr string) (net.Conn, error) {
	targetHost, targetPortStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid target address %q: %w", targetAddr, err)
	}
	if err := common.ValidateTargetHost(targetHost, cfg.AllowLocal); err != nil {
		return nil, err
	}
	targetPort, err := strconv.Atoi(targetPortStr)
	if err != nil || targetPort < 1 || targetPort > 65535 {
		return nil, fmt.Errorf("invalid target port %q", targetPortStr)
	}

	dialer := &net.Dialer{
		Timeout: 15 * time.Second,
		Control: common.SafeDialerControl(cfg.AllowLocal || cfg.AllowLocalUpstream),
	}
	upstreamAddr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	rawConn, err := dialer.DialContext(ctx, "tcp", upstreamAddr)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", upstreamAddr, err)
	}

	scheme := strings.ToLower(strings.TrimSpace(cfg.Scheme))
	var conn net.Conn = rawConn
	if scheme == "https" {
		tlsConn := tls.Client(rawConn, &tls.Config{
			ServerName: cfg.Host,
			MinVersion: tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = rawConn.Close()
			return nil, fmt.Errorf("upstream TLS handshake: %w", err)
		}
		conn = tlsConn
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
		defer conn.SetDeadline(time.Time{})
	} else {
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		defer conn.SetDeadline(time.Time{})
	}

	switch scheme {
	case "http", "https":
		if err := handshakeHTTPConnect(conn, cfg, targetAddr); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	case "socks5":
		if err := handshakeSOCKS5(conn, cfg, targetHost, uint16(targetPort)); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	default:
		_ = conn.Close()
		return nil, fmt.Errorf("unsupported proxy scheme %q", cfg.Scheme)
	}
}

func handshakeHTTPConnect(conn net.Conn, cfg UpstreamConfig, targetAddr string) error {
	for _, r := range targetAddr {
		if r <= 0x20 || r == 0x7f {
			return fmt.Errorf("invalid control/whitespace character in CONNECT target %q", targetAddr)
		}
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "CONNECT %s HTTP/1.1\r\n", targetAddr)
	fmt.Fprintf(&sb, "Host: %s\r\n", targetAddr)
	fmt.Fprintf(&sb, "Proxy-Connection: Keep-Alive\r\n")
	if cfg.Username != "" || cfg.Password != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(cfg.Username + ":" + cfg.Password))
		fmt.Fprintf(&sb, "Proxy-Authorization: Basic %s\r\n", cred)
	}
	sb.WriteString("\r\n")
	if _, err := io.WriteString(conn, sb.String()); err != nil {
		return fmt.Errorf("write CONNECT: %w", err)
	}

	lr := &io.LimitedReader{R: conn, N: MaxHandshakeBytes}
	br := bufio.NewReader(lr)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		if lr.N <= 0 {
			return fmt.Errorf("upstream CONNECT response exceeded %d bytes", MaxHandshakeBytes)
		}
		return fmt.Errorf("read CONNECT response: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upstream CONNECT rejected with HTTP %d (%s)", resp.StatusCode, resp.Status)
	}
	return nil
}

func handshakeSOCKS5(conn net.Conn, cfg UpstreamConfig, targetHost string, targetPort uint16) error {
	hasAuth := cfg.Username != "" || cfg.Password != ""
	if hasAuth {
		if len(cfg.Username) > 255 || len(cfg.Password) > 255 {
			return errors.New("SOCKS5 username/password exceeds 255 bytes")
		}
		if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			return fmt.Errorf("socks5 greeting: %w", err)
		}
	} else {
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			return fmt.Errorf("socks5 greeting: %w", err)
		}
	}

	var methodResp [2]byte
	if _, err := io.ReadFull(conn, methodResp[:]); err != nil {
		return fmt.Errorf("socks5 method response: %w", err)
	}
	if methodResp[0] != 0x05 {
		return fmt.Errorf("socks5 invalid version %d", methodResp[0])
	}
	switch methodResp[1] {
	case 0x00:
		// No auth required
	case 0x02:
		if !hasAuth {
			return errors.New("socks5 upstream requires username/password authentication")
		}
		buf := make([]byte, 0, 3+len(cfg.Username)+len(cfg.Password))
		buf = append(buf, 0x01, byte(len(cfg.Username)))
		buf = append(buf, cfg.Username...)
		buf = append(buf, byte(len(cfg.Password)))
		buf = append(buf, cfg.Password...)
		if _, err := conn.Write(buf); err != nil {
			return fmt.Errorf("socks5 auth write: %w", err)
		}
		var authResp [2]byte
		if _, err := io.ReadFull(conn, authResp[:]); err != nil {
			return fmt.Errorf("socks5 auth response: %w", err)
		}
		if authResp[1] != 0x00 {
			return fmt.Errorf("socks5 authentication rejected (status=0x%02x)", authResp[1])
		}
	default:
		return fmt.Errorf("socks5 unsupported auth method 0x%02x", methodResp[1])
	}

	// Always send ATYP=0x03 (domain name) so DNS resolution occurs on the remote proxy (zero local DNS leak).
	if len(targetHost) > 255 {
		return errors.New("target host exceeds 255 bytes")
	}
	req := make([]byte, 0, 7+len(targetHost))
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(targetHost)))
	req = append(req, targetHost...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], targetPort)
	req = append(req, portBuf[:]...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 connect write: %w", err)
	}

	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return fmt.Errorf("socks5 connect header: %w", err)
	}
	if hdr[0] != 0x05 {
		return fmt.Errorf("socks5 invalid reply version %d", hdr[0])
	}
	if hdr[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed (reply=0x%02x)", hdr[1])
	}
	var discardLen int
	switch hdr[3] {
	case 0x01:
		discardLen = 4 + 2
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return err
		}
		discardLen = int(l[0]) + 2
	case 0x04:
		discardLen = 16 + 2
	default:
		return fmt.Errorf("socks5 unknown address type 0x%02x", hdr[3])
	}
	if discardLen > MaxHandshakeBytes {
		return errors.New("socks5 reply address too large")
	}
	if _, err := io.CopyN(io.Discard, conn, int64(discardLen)); err != nil {
		return fmt.Errorf("socks5 consume bind addr: %w", err)
	}
	return nil
}
