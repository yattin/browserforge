package cdp

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// WSConn is a zero-dependency RFC 6455 client WebSocket connection.
type WSConn struct {
	conn net.Conn
	br   *bufio.Reader
	wmu  sync.Mutex
}

// DialWS performs an RFC 6455 HTTP/1.1 WebSocket upgrade to wsURL (ws://...).
func DialWS(wsURL string, timeout time.Duration) (*WSConn, error) {
	u, err := url.Parse(wsURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "ws" {
		return nil, fmt.Errorf("unsupported websocket scheme %q (expected ws)", u.Scheme)
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	conn, err := net.DialTimeout("tcp", host, timeout)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	var keyBytes [16]byte
	if _, err := rand.Read(keyBytes[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	secKey := base64.StdEncoding.EncodeToString(keyBytes[:])

	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	reqStr := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		path, u.Host, secKey)
	if _, err := io.WriteString(conn, reqStr); err != nil {
		_ = conn.Close()
		return nil, err
	}

	br := bufio.NewReaderSize(conn, 64*1024)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ws handshake read: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = conn.Close()
		return nil, fmt.Errorf("ws handshake failed: HTTP %d", resp.StatusCode)
	}
	expectedAccept := computeWSAccept(secKey)
	if strings.TrimSpace(resp.Header.Get("Sec-WebSocket-Accept")) != expectedAccept {
		_ = conn.Close()
		return nil, errors.New("ws handshake invalid Sec-WebSocket-Accept")
	}
	_ = conn.SetDeadline(time.Time{})
	return &WSConn{conn: conn, br: br}, nil
}

func computeWSAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

func (c *WSConn) Close() error {
	_ = c.writeFrame(0x8, nil)
	return c.conn.Close()
}

func (c *WSConn) WriteText(payload []byte) error {
	return c.writeFrame(0x1, payload)
}

func (c *WSConn) writeFrame(opcode byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	var maskKey [4]byte
	if _, err := rand.Read(maskKey[:]); err != nil {
		return err
	}

	hdr := make([]byte, 0, 14)
	hdr = append(hdr, 0x80|(opcode&0x0f))
	n := len(payload)
	switch {
	case n <= 125:
		hdr = append(hdr, 0x80|byte(n))
	case n <= 65535:
		hdr = append(hdr, 0x80|126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 0x80|127)
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(n))
		hdr = append(hdr, l[:]...)
	}
	hdr = append(hdr, maskKey[:]...)

	masked := make([]byte, n)
	for i := 0; i < n; i++ {
		masked[i] = payload[i] ^ maskKey[i&3]
	}

	if _, err := c.conn.Write(hdr); err != nil {
		return err
	}
	if n > 0 {
		if _, err := c.conn.Write(masked); err != nil {
			return err
		}
	}
	return nil
}

// ReadText reads the next complete text/binary message, handling fragmentation and control frames.
func (c *WSConn) ReadText(timeout time.Duration) ([]byte, error) {
	if timeout > 0 {
		_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
		defer c.conn.SetReadDeadline(time.Time{})
	}
	var assembled []byte
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
			return nil, err
		}
		fin := (hdr[0] & 0x80) != 0
		opcode := hdr[0] & 0x0f
		masked := (hdr[1] & 0x80) != 0
		plen := uint64(hdr[1] & 0x7f)

		switch plen {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(c.br, ext[:]); err != nil {
				return nil, err
			}
			plen = uint64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(c.br, ext[:]); err != nil {
				return nil, err
			}
			plen = binary.BigEndian.Uint64(ext[:])
		}
		// Cap single frame at 64 MiB (e.g. large full-page PNG screenshots).
		if plen > 64*1024*1024 {
			return nil, fmt.Errorf("ws frame too large: %d bytes", plen)
		}

		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(c.br, maskKey[:]); err != nil {
				return nil, err
			}
		}
		data := make([]byte, plen)
		if plen > 0 {
			if _, err := io.ReadFull(c.br, data); err != nil {
				return nil, err
			}
			if masked {
				for i := range data {
					data[i] ^= maskKey[i&3]
				}
			}
		}

		switch opcode {
		case 0x8: // Close
			return nil, io.EOF
		case 0x9: // Ping
			_ = c.writeFrame(0xA, data)
			continue
		case 0xA: // Pong
			continue
		case 0x0, 0x1, 0x2:
			if len(assembled)+len(data) > 64*1024*1024 {
				return nil, fmt.Errorf("assembled ws message exceeded 64 MiB cap")
			}
			assembled = append(assembled, data...)
			if fin {
				return assembled, nil
			}
		default:
			return nil, fmt.Errorf("unexpected ws opcode 0x%x", opcode)
		}
	}
}
