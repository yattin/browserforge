package cdp

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestWSRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		key := req.Header.Get("Sec-WebSocket-Key")
		accept := computeWSAccept(key)
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "+accept+"\r\n\r\n")

		// Read one masked client text frame.
		var hdr [2]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return
		}
		plen := int(hdr[1] & 0x7f)
		var mask [4]byte
		_, _ = io.ReadFull(br, mask[:])
		data := make([]byte, plen)
		_, _ = io.ReadFull(br, data)
		for i := range data {
			data[i] ^= mask[i&3]
		}

		// Reply with an unmasked server text frame (>125 bytes to test 16-bit extended length).
		reply := []byte(strings.Repeat(string(data), 10))
		outHdr := []byte{0x81, 126, 0, 0}
		binary.BigEndian.PutUint16(outHdr[2:4], uint16(len(reply)))
		_, _ = conn.Write(outHdr)
		_, _ = conn.Write(reply)
	}()

	wsURL := fmt.Sprintf("ws://%s/devtools/page/test", ln.Addr().String())
	ws, err := DialWS(wsURL, 5*time.Second)
	if err != nil {
		t.Fatalf("DialWS: %v", err)
	}
	defer ws.Close()

	msg := "hello-browserforge!"
	if err := ws.WriteText([]byte(msg)); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	got, err := ws.ReadText(5 * time.Second)
	if err != nil {
		t.Fatalf("ReadText: %v", err)
	}
	want := strings.Repeat(msg, 10)
	if string(got) != want {
		t.Fatalf("WS echo mismatch: got len %d, want len %d", len(got), len(want))
	}
}
