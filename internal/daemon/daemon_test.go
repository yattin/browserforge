package daemon

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"browserforge/internal/store"
)

func TestDaemonAuthOriginAndLifecycle(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	srv, err := NewServer(st)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve() }()
	defer srv.Close()

	// 1. Probe with valid token from daemon.json succeeds.
	state, err := Probe(st.DataDir)
	if err != nil || state.Port != srv.State().Port {
		t.Fatalf("Probe failed: %v", err)
	}

	// 2. Missing / wrong Authorization header -> 401.
	cli := &http.Client{Timeout: 3 * time.Second}
	resp, err := cli.Get(fmt.Sprintf("http://127.0.0.1:%d/health", state.Port))
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", resp.StatusCode)
	}

	// 3. Cross-origin request with Origin header -> 403 even with valid token.
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/health", state.Port), nil)
	req.Header.Set("Authorization", "Bearer "+state.Token)
	req.Header.Set("Origin", "https://evil.example.com")
	resp2, err := cli.Do(req)
	if err != nil {
		t.Fatalf("GET /health with Origin: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 with Origin header, got %d", resp2.StatusCode)
	}

	// 3b. KernelOverride pointing to arbitrary non-browser executable -> 403.
	if err := validateDaemonKernelOverride(`C:\Windows\System32\cmd.exe`); err == nil {
		t.Fatalf("expected cmd.exe kernel override to be rejected")
	}
	if err := validateDaemonKernelOverride(`D:\Beryl\chrome.exe`); err != nil {
		t.Fatalf("expected chrome.exe kernel override to be allowed, got %v", err)
	}

	// 3c. Panel single-use ticket -> HttpOnly cookie -> /panel/api/status OK, replay fails.
	enterURL, err := srv.CreatePanelEnterURL()
	if err != nil {
		t.Fatalf("CreatePanelEnterURL: %v", err)
	}
	noRedir := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	enterResp, err := noRedir.Get(enterURL)
	if err != nil {
		t.Fatalf("GET /panel/enter: %v", err)
	}
	_ = enterResp.Body.Close()
	if enterResp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from /panel/enter, got %d", enterResp.StatusCode)
	}
	var panelCookie *http.Cookie
	for _, c := range enterResp.Cookies() {
		if c.Name == panelCookieName {
			panelCookie = c
		}
	}
	if panelCookie == nil || !panelCookie.HttpOnly {
		t.Fatalf("expected HttpOnly %s cookie", panelCookieName)
	}
	// Replay of same ticket must fail 401.
	replayResp, err := noRedir.Get(enterURL)
	if err != nil {
		t.Fatalf("replay /panel/enter: %v", err)
	}
	_ = replayResp.Body.Close()
	if replayResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on replayed ticket, got %d", replayResp.StatusCode)
	}
	// Authenticated /panel/api/status with cookie succeeds.
	stReq, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/panel/api/status", state.Port), nil)
	stReq.AddCookie(panelCookie)
	stResp, err := cli.Do(stReq)
	if err != nil {
		t.Fatalf("GET /panel/api/status: %v", err)
	}
	_ = stResp.Body.Close()
	if stResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /panel/api/status, got %d", stResp.StatusCode)
	}
	// POST /panel/api/stop without X-BF-Panel header must fail 403.
	postReq, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/panel/api/stop", state.Port), nil)
	postReq.AddCookie(panelCookie)
	postResp, err := cli.Do(postReq)
	if err != nil {
		t.Fatalf("POST /panel/api/stop: %v", err)
	}
	_ = postResp.Body.Close()
	if postResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 without X-BF-Panel header, got %d", postResp.StatusCode)
	}

	// 4. RemoteShutdown stops server cleanly.
	if err := RemoteShutdown(state); err != nil {
		t.Fatalf("RemoteShutdown: %v", err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("daemon did not exit after RemoteShutdown")
	}
}
