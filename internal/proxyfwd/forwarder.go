package proxyfwd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"browserforge/internal/common"
	"browserforge/internal/kernel"
	"browserforge/internal/store"
)

// Server is a local 127.0.0.1 HTTP/HTTPS forwarding proxy that bridges Chromium to an authenticated upstream.
type Server struct {
	cfg      UpstreamConfig
	listener net.Listener
	httpSrv  *http.Server
}

func NewServer(cfg UpstreamConfig) (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:      cfg,
		listener: ln,
	}
	s.httpSrv = &http.Server{
		Handler:           http.HandlerFunc(s.handleHTTP),
		ReadHeaderTimeout: 15 * time.Second,
		MaxHeaderBytes:    MaxHandshakeBytes,
	}
	return s, nil
}

func (s *Server) Port() int {
	return s.listener.Addr().(*net.TCPAddr).Port
}

func (s *Server) Serve() error {
	err := s.httpSrv.Serve(s.listener)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.httpSrv.Shutdown(ctx)
	return s.listener.Close()
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	s.handlePlainHTTP(w, r)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if !strings.Contains(target, ":") {
		target += ":443"
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		http.Error(w, "bad target host", http.StatusBadRequest)
		return
	}
	if err := common.ValidateTargetHost(host, s.cfg.AllowLocal); err != nil {
		http.Error(w, "blocked by SSRF protection", http.StatusForbidden)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	upConn, err := DialUpstreamThrough(ctx, s.cfg, target)
	if err != nil {
		if errors.Is(err, common.ErrSSRFBlocked) {
			http.Error(w, "blocked by SSRF protection", http.StatusForbidden)
			return
		}
		http.Error(w, "upstream connect failed", http.StatusBadGateway)
		return
	}
	defer upConn.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	if tc, ok := upConn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	if tc, ok := clientConn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if clientBuf.Reader.Buffered() > 0 {
			_, _ = io.CopyN(upConn, clientBuf, int64(clientBuf.Reader.Buffered()))
		}
		_, _ = io.Copy(upConn, clientConn)
		if tc, ok := upConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		// Prevent half-open peer from hanging indefinitely.
		_ = upConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, upConn)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	}()
	wg.Wait()
}

func (s *Server) handlePlainHTTP(w http.ResponseWriter, r *http.Request) {
	targetHost := r.URL.Hostname()
	if targetHost == "" {
		targetHost = r.Host
	}
	targetPort := r.URL.Port()
	if targetPort == "" {
		targetPort = "80"
	}
	if err := common.ValidateTargetHost(targetHost, s.cfg.AllowLocal); err != nil {
		http.Error(w, "blocked by SSRF protection", http.StatusForbidden)
		return
	}

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return DialUpstreamThrough(ctx, s.cfg, addr)
		},
		DisableCompression: true,
	}
	defer tr.CloseIdleConnections()

	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	if outReq.URL.Scheme == "" {
		outReq.URL.Scheme = "http"
	}
	if outReq.URL.Host == "" {
		outReq.URL.Host = net.JoinHostPort(targetHost, targetPort)
	}
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authorization")

	resp, err := tr.RoundTrip(outReq)
	if err != nil {
		if errors.Is(err, common.ErrSSRFBlocked) {
			http.Error(w, "blocked by SSRF protection", http.StatusForbidden)
			return
		}
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

type readyBanner struct {
	Port int `json:"port"`
	PID  int `json:"pid"`
}

// RunSubprocess implements the hidden `browserforge _forwarder` command.
// Credentials are received strictly via stdin JSON (never argv).
func RunSubprocess() error {
	lr := &io.LimitedReader{R: os.Stdin, N: MaxHandshakeBytes}
	raw, err := io.ReadAll(lr)
	if err != nil {
		return fmt.Errorf("read forwarder config from stdin: %w", err)
	}
	var cfg UpstreamConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("parse forwarder config: %w", err)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		return err
	}
	banner, _ := json.Marshal(readyBanner{Port: srv.Port(), PID: os.Getpid()})
	_, _ = fmt.Fprintln(os.Stdout, string(banner))

	if cfg.RuntimeFile != "" {
		go watchBrowserLifetime(cfg.RuntimeFile, srv)
	}
	return srv.Serve()
}

func watchBrowserLifetime(runtimeFile string, srv *Server) {
	myPID := os.Getpid()
	startupDeadline := time.Now().Add(45 * time.Second)
	// Grace period for parent to launch browser and write runtime.json.
	time.Sleep(8 * time.Second)
	seenBrowser := false
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		raw, err := os.ReadFile(runtimeFile)
		if err != nil {
			if seenBrowser || time.Now().After(startupDeadline) {
				_ = srv.Close()
				return
			}
			continue
		}
		var st store.RuntimeState
		if json.Unmarshal(raw, &st) != nil || st.BrowserPID <= 0 {
			if time.Now().After(startupDeadline) && !seenBrowser {
				_ = srv.Close()
				return
			}
			continue
		}
		// If profile was restarted with a newer forwarder, exit immediately so we never linger.
		if st.ProxyPID > 0 && st.ProxyPID != myPID {
			_ = srv.Close()
			return
		}
		seenBrowser = true
		if !kernel.IsProcessAlive(st.BrowserPID) {
			_ = srv.Close()
			return
		}
	}
}

// SpawnSubprocess launches `browserforge _forwarder`, feeds cfg over stdin, and waits for the bound local port.
func SpawnSubprocess(cfg UpstreamConfig, logFile string) (pid int, port int, err error) {
	exePath, err := os.Executable()
	if err != nil {
		return 0, 0, err
	}
	cmd := exec.Command(exePath, "_forwarder")
	common.HideCmdWindow(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return 0, 0, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, 0, err
	}
	if logFile != "" {
		if f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
			cmd.Stderr = f
			defer f.Close()
		}
	}
	if err := cmd.Start(); err != nil {
		return 0, 0, fmt.Errorf("start forwarder subprocess: %w", err)
	}

	payload, err := json.Marshal(cfg)
	if err != nil {
		_ = kernel.TerminateProcess(cmd.Process.Pid)
		return 0, 0, err
	}
	if _, err := stdin.Write(payload); err != nil {
		_ = kernel.TerminateProcess(cmd.Process.Pid)
		return 0, 0, err
	}
	_ = stdin.Close()

	type res struct {
		banner readyBanner
		err    error
	}
	ch := make(chan res, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		if !sc.Scan() {
			if err := sc.Err(); err != nil {
				ch <- res{err: err}
			} else {
				ch <- res{err: errors.New("forwarder exited before reporting port")}
			}
			return
		}
		var b readyBanner
		if err := json.Unmarshal([]byte(sc.Text()), &b); err != nil {
			ch <- res{err: fmt.Errorf("invalid forwarder banner: %w", err)}
			return
		}
		ch <- res{banner: b}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			_ = kernel.TerminateProcess(cmd.Process.Pid)
			return 0, 0, r.err
		}
		_ = cmd.Process.Release()
		return r.banner.PID, r.banner.Port, nil
	case <-time.After(10 * time.Second):
		_ = kernel.TerminateProcess(cmd.Process.Pid)
		return 0, 0, errors.New("timed out waiting for forwarder startup")
	}
}
