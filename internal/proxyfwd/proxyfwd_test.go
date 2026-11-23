package proxyfwd

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestForwarderBasicAuthAndSSRFBlock(t *testing.T) {
	// Target HTTP server on loopback (used only when AllowLocal=true).
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"ip":"203.0.113.10","country_code":"US","timezone":{"id":"America/New_York"}}`)
	}))
	defer target.Close()

	// Mock upstream HTTP CONNECT + Basic Auth proxy.
	const wantUser, wantPass = "alice", "s3cr3t!"
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(wantUser+":"+wantPass))

	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upLn.Close()
	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				br := bufio.NewReader(conn)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				if req.Header.Get("Proxy-Authorization") != wantAuth {
					_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
					return
				}
				dst, err := net.DialTimeout("tcp", req.Host, 5*time.Second)
				if err != nil {
					_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer dst.Close()
				_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
				go io.Copy(dst, br)
				_, _ = io.Copy(conn, dst)
			}(c)
		}
	}()
	upPort := upLn.Addr().(*net.TCPAddr).Port

	// 1. SSRF must block 127.0.0.1 & 169.254.169.254 when AllowLocal=false.
	srvBlocked, err := NewServer(UpstreamConfig{
		Scheme:             "http",
		Host:               "127.0.0.1",
		Port:               upPort,
		Username:           wantUser,
		Password:           wantPass,
		AllowLocal:         false,
		AllowLocalUpstream: true,
	})
	if err != nil {
		t.Fatalf("NewServer blocked: %v", err)
	}
	defer srvBlocked.Close()
	go srvBlocked.Serve()

	proxyURLBlocked, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", srvBlocked.Port()))
	clientBlocked := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURLBlocked)},
		Timeout:   5 * time.Second,
	}
	for _, forbiddenURL := range []string{target.URL, "http://169.254.169.254/latest/meta-data/"} {
		resp, err := clientBlocked.Get(forbiddenURL)
		if err != nil {
			t.Fatalf("GET %s unexpected transport error: %v", forbiddenURL, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 SSRF block for %s, got %d", forbiddenURL, resp.StatusCode)
		}
	}

	// 2. When AllowLocal=true (explicit test mode), ProbeUpstream succeeds through authenticated upstream.
	probeRes := ProbeUpstream(context.Background(), UpstreamConfig{
		Scheme:             "http",
		Host:               "127.0.0.1",
		Port:               upPort,
		Username:           wantUser,
		Password:           wantPass,
		AllowLocal:         true,
		AllowLocalUpstream: true,
	}, target.URL)
	if !probeRes.OK || probeRes.ExitIP != "203.0.113.10" || probeRes.Timezone != "America/New_York" {
		t.Fatalf("expected probe success, got %+v", probeRes)
	}

	// 3. Oversized probe response (> 1 MiB) must be rejected.
	bigTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("A", MaxProbeBytes+100))
	}))
	defer bigTarget.Close()
	bigRes := ProbeUpstream(context.Background(), UpstreamConfig{
		Scheme:             "http",
		Host:               "127.0.0.1",
		Port:               upPort,
		Username:           wantUser,
		Password:           wantPass,
		AllowLocal:         true,
		AllowLocalUpstream: true,
	}, bigTarget.URL)
	if bigRes.OK || !strings.Contains(bigRes.Error, "exceeded") {
		t.Fatalf("expected >1MiB probe to fail cap check, got %+v", bigRes)
	}
}
