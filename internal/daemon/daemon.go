package daemon

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"browserforge/internal/common"
	"browserforge/internal/launcher"
	"browserforge/internal/store"
)

const maxBodyBytes = 64 * 1024

type DaemonState struct {
	PID       int    `json:"pid"`
	Port      int    `json:"port"`
	Token     string `json:"token"`
	Version   string `json:"version"`
	StartedAt string `json:"started_at"`
}

func StatePath(dataDir string) string {
	return filepath.Join(dataDir, "daemon.json")
}

func LoadState(dataDir string) (*DaemonState, error) {
	raw, err := os.ReadFile(StatePath(dataDir))
	if err != nil {
		return nil, err
	}
	var st DaemonState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Server hosts a loopback-only authenticated foreground launcher so background CLI/Agents
// can pop up visible headed browser windows inside the user's interactive desktop session.
type Server struct {
	st           *store.Store
	state        DaemonState
	listener     net.Listener
	httpSrv      *http.Server
	done         chan struct{}
	panelSecret  string
	panelMu      sync.Mutex
	panelTickets map[string]time.Time
}

func NewServer(st *store.Store) (*Server, error) {
	// If an active daemon is already healthy, refuse to shadow it.
	if existing, err := Probe(st.DataDir); err == nil && existing != nil {
		return nil, fmt.Errorf("daemon already running (pid=%d port=%d)", existing.PID, existing.Port)
	}
	tok, err := common.RandomHex(32)
	if err != nil {
		return nil, err
	}
	panelSec, err := common.RandomHex(32)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	s := &Server{
		st: st,
		state: DaemonState{
			PID:       os.Getpid(),
			Port:      port,
			Token:     tok,
			Version:   common.AppVersion,
			StartedAt: time.Now().UTC().Format(time.RFC3339),
		},
		listener:     ln,
		done:         make(chan struct{}),
		panelSecret:  panelSec,
		panelTickets: map[string]time.Time{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/panel", http.StatusFound)
	})
	mux.HandleFunc("/health", s.withAuth(s.handleHealth))
	mux.HandleFunc("/start", s.withAuth(s.handleStart))
	mux.HandleFunc("/stop", s.withAuth(s.handleStop))
	mux.HandleFunc("/shutdown", s.withAuth(s.handleShutdown))
	mux.HandleFunc("/panel-ticket", s.withAuth(s.handlePanelTicket))
	mux.HandleFunc("/panel/enter", s.handlePanelEnter)
	mux.HandleFunc("/panel", s.handlePanelPage)
	mux.HandleFunc("/panel/api/status", s.withPanelAuth(s.handlePanelStatus))
	mux.HandleFunc("/panel/api/start", s.withPanelAuth(s.handlePanelStart))
	mux.HandleFunc("/panel/api/stop", s.withPanelAuth(s.handlePanelStop))

	s.httpSrv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    maxBodyBytes,
	}

	raw, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	if err := common.WriteFileAtomic(StatePath(st.DataDir), raw, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return s, nil
}

func (s *Server) State() DaemonState   { return s.state }
func (s *Server) Done() <-chan struct{} { return s.done }

func (s *Server) Serve() error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			_ = s.Close()
		case <-s.done:
		}
	}()
	defer func() {
		signal.Stop(sigCh)
		_ = os.Remove(StatePath(s.st.DataDir))
	}()

	err := s.httpSrv.Serve(s.listener)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s *Server) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.httpSrv.Shutdown(ctx)
	_ = s.listener.Close()
	_ = os.Remove(StatePath(s.st.DataDir))
	return nil
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Block browser-initiated cross-origin requests (CSRF / DNS rebinding).
		if r.Header.Get("Origin") != "" {
			writeErr(w, http.StatusForbidden, "cross-origin requests are forbidden")
			return
		}
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		want := "Bearer " + s.state.Token
		if len(auth) != len(want) || subtle.ConstantTimeCompare([]byte(auth), []byte(want)) != 1 {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"pid":        s.state.PID,
		"port":       s.state.Port,
		"version":    s.state.Version,
		"started_at": s.state.StartedAt,
	})
}

var allowedKernelNames = map[string]bool{
	"chrome.exe":       true,
	"msedge.exe":       true,
	"chromium.exe":     true,
	"chrome":           true,
	"chromium":         true,
	"chromium-browser": true,
	"google-chrome":    true,
}

func validateDaemonKernelOverride(exe string) error {
	s := strings.TrimSpace(exe)
	if s == "" {
		return nil
	}
	base := strings.ToLower(filepath.Base(s))
	if !allowedKernelNames[base] {
		return fmt.Errorf("disallowed kernel override executable %q", base)
	}
	return nil
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req launcher.StartRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if err := validateDaemonKernelOverride(req.KernelOverride); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	res, err := launcher.StartProfile(s.st, req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	res.ViaDaemon = true
	writeJSON(w, http.StatusOK, res)
}

type StopRequest struct {
	ProfileRef string `json:"profile_ref,omitempty"`
	All        bool   `json:"all,omitempty"`
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req StopRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	var stopped []string
	if req.All {
		list, err := s.st.ListProfiles()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, p := range list {
			if rt, _ := s.st.LoadRuntime(p.ID); rt != nil {
				_ = launcher.StopProfile(s.st, p.ID)
				stopped = append(stopped, p.ID)
			}
		}
	} else {
		rec, err := s.st.FindProfile(req.ProfileRef)
		if err != nil {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		if err := launcher.StopProfile(s.st, rec.ID); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		stopped = append(stopped, rec.ID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "stopped": stopped})
}

func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "stopping": s.state.PID})
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = s.Close()
	}()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"ok": false, "error": msg})
}

// --- Client helpers ---

func doRequest(st *DaemonState, method, path string, body any, timeout time.Duration) ([]byte, int, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", st.Port, path), rdr)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+st.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	cli := &http.Client{Timeout: timeout}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return raw, resp.StatusCode, err
}

// Probe checks if a live, authenticated foreground daemon is running for dataDir.
func Probe(dataDir string) (*DaemonState, error) {
	st, err := LoadState(dataDir)
	if err != nil {
		return nil, err
	}
	_, code, err := doRequest(st, http.MethodGet, "/health", nil, 1500*time.Millisecond)
	if err != nil || code != http.StatusOK {
		return nil, errors.New("daemon unreachable")
	}
	return st, nil
}

// RemoteStart asks the running foreground daemon to launch a profile on the user's desktop.
func RemoteStart(st *DaemonState, req launcher.StartRequest) (*launcher.StartResult, error) {
	raw, code, err := doRequest(st, http.MethodPost, "/start", req, 35*time.Second)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		var er struct{ Error string `json:"error"` }
		_ = json.Unmarshal(raw, &er)
		if er.Error != "" {
			return nil, errors.New(er.Error)
		}
		return nil, fmt.Errorf("daemon start failed: HTTP %d", code)
	}
	var res launcher.StartResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (s *Server) handlePanelTicket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	u, err := s.CreatePanelEnterURL()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "url": u})
}

// RemoteShutdown gracefully shuts down the running foreground daemon.
func RemoteShutdown(st *DaemonState) error {
	_, code, err := doRequest(st, http.MethodPost, "/shutdown", nil, 5*time.Second)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("daemon shutdown failed: HTTP %d", code)
	}
	return nil
}

// RequestPanelURL requests a fresh single-use authenticated panel URL from a running daemon.
func RequestPanelURL(st *DaemonState) (string, error) {
	raw, code, err := doRequest(st, http.MethodPost, "/panel-ticket", nil, 3*time.Second)
	if err != nil {
		return "", err
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("panel-ticket failed: HTTP %d", code)
	}
	var res struct {
		OK  bool   `json:"ok"`
		URL string `json:"url"`
	}
	if err := json.Unmarshal(raw, &res); err != nil || res.URL == "" {
		return "", errors.New("invalid panel-ticket response")
	}
	return res.URL, nil
}
