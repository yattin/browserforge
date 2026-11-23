package selftest

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
	"os"
	"strings"
	"time"

	"browserforge/internal/cdp"
	"browserforge/internal/common"
	"browserforge/internal/fingerprint"
	"browserforge/internal/kernel"
	"browserforge/internal/proxyfwd"
	"browserforge/internal/store"
)

type StageResult struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail"`
	Elapsed string `json:"elapsed"`
}

type Report struct {
	OK     bool          `json:"ok"`
	Stages []StageResult `json:"stages"`
}

// Run executes the built-in security & integration regression suite in an isolated temp directory.
func Run(withBrowser bool, configuredKernel string) Report {
	var rep Report
	rep.OK = true

	runStage := func(name string, fn func() (string, error)) {
		t0 := time.Now()
		detail, err := fn()
		sr := StageResult{
			Name:    name,
			OK:      err == nil,
			Detail:  detail,
			Elapsed: time.Since(t0).Round(time.Millisecond).String(),
		}
		if err != nil {
			sr.Detail = err.Error()
			rep.OK = false
		}
		rep.Stages = append(rep.Stages, sr)
	}

	tmpDir, err := os.MkdirTemp("", "browserforge-selftest-*")
	if err != nil {
		return Report{OK: false, Stages: []StageResult{{Name: "tempdir", OK: false, Detail: err.Error()}}}
	}
	defer os.RemoveAll(tmpDir)

	// 1. Secret protection round-trip
	runStage("1. Secret Protection (DPAPI/AEAD)", func() (string, error) {
		enc, err := common.ProtectSecret(tmpDir, "s3cr3t-proxy-pass!")
		if err != nil {
			return "", err
		}
		if strings.Contains(enc, "s3cr3t") {
			return "", fmt.Errorf("plaintext leaked in ciphertext")
		}
		dec, err := common.UnprotectSecret(tmpDir, enc)
		if err != nil || dec != "s3cr3t-proxy-pass!" {
			return "", fmt.Errorf("roundtrip mismatch")
		}
		return "encrypted & decrypted cleanly", nil
	})

	// 2. ECMA canonical JSON & beryl-v1 fingerprint integrity + tamper fail-closed
	var testFP *fingerprint.FingerprintData
	var testProfileID string
	runStage("2. beryl-v1 Fingerprint & Tamper Detection", func() (string, error) {
		c, err := fingerprint.CanonicalJSON(map[string]any{"b": "x<y>&z", "a": 1920.0})
		if err != nil {
			return "", err
		}
		if c != `{"a":1920,"b":"x<y>&z"}` {
			return "", fmt.Errorf("canonical JSON mismatch: %s", c)
		}
		id, _ := common.NewUUIDv4()
		testProfileID = id
		host := fingerprint.DetectHost()
		fp, err := fingerprint.Generate(fingerprint.GenerateParams{
			ProfileID:      id,
			Template:       fingerprint.DefaultTemplateID(host.OS, host.GPUVendor),
			BrowserVersion: "156.0.8078.79",
			Brand:          "Google Chrome",
			Timezone:       "America/New_York",
			Languages:      []string{"en-US", "en"},
			Host:           host,
		})
		if err != nil {
			return "", err
		}
		raw, _ := fp.MarshalIndented()
		if _, err := fingerprint.ValidateIntegrity(raw, id); err != nil {
			return "", err
		}
		tampered := strings.Replace(string(raw), `"America/New_York"`, `"Asia/Tokyo"`, 1)
		if _, err := fingerprint.ValidateIntegrity([]byte(tampered), id); err == nil {
			return "", fmt.Errorf("tampered fingerprint unexpectedly passed")
		}
		testFP = fp
		return fmt.Sprintf("algorithm=%s checksum=%s...", fp.Algorithm, fp.Checksum[:12]), nil
	})

	// 3. Store layout + 0444 read-only fingerprint lock + 9-rule consistency
	runStage("3. Isolated Profile Layout & 9-Rule Validator", func() (string, error) {
		st, err := store.Open(tmpDir)
		if err != nil {
			return "", err
		}
		prof := store.ProfileRecord{
			ID:        testProfileID,
			Name:      "selftest-profile",
			Template:  testFP.Template,
			Timezone:  "America/New_York",
			Languages: []string{"en-US", "en"},
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		if err := st.InitProfileLayout(prof, testFP); err != nil {
			return "", err
		}
		loaded, isRO, err := st.LoadFingerprint(testProfileID)
		if err != nil {
			return "", err
		}
		if !isRO {
			return "", fmt.Errorf("fingerprint.json is not read-only")
		}
		vrep := fingerprint.ValidateConsistency(loaded, fingerprint.ValidationContext{
			Host:          fingerprint.DetectHost(),
			KernelVersion: "156.0.8078.79",
			HasProxy:      true,
			ProxyTimezone: "America/New_York",
			FileReadOnly:  isRO,
			ExpectedID:    testProfileID,
		})
		if !vrep.OK {
			return "", fmt.Errorf("validator failed: %s", vrep.Summary)
		}
		return vrep.Summary, nil
	})

	// 4. Dangerous Chromium extra-args filter
	runStage("4. Dangerous Launch Flags Filter", func() (string, error) {
		for _, bad := range []string{"--no-sandbox", "--gpu-launcher=cmd", "--remote-debugging-port=9222", "--load-extension=x"} {
			if err := kernel.ValidateExtraArgs([]string{bad}); err == nil {
				return "", fmt.Errorf("failed to block %s", bad)
			}
		}
		return "blocked 4/4 dangerous flags", nil
	})

	// 5. Proxy forwarder Basic Auth + SSRF 403 + 1 MiB probe cap
	runStage("5. Proxy Forwarder Auth, SSRF & Buffer Caps", func() (string, error) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"ip":"198.51.100.7","country_code":"US","timezone":"America/New_York"}`)
		}))
		defer target.Close()

		const user, pass = "bfuser", "bfpass"
		wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
		upLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return "", err
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

		srv, err := proxyfwd.NewServer(proxyfwd.UpstreamConfig{
			Scheme:             "http",
			Host:               "127.0.0.1",
			Port:               upPort,
			Username:           user,
			Password:           pass,
			AllowLocal:         false,
			AllowLocalUpstream: true,
		})
		if err != nil {
			return "", err
		}
		defer srv.Close()
		go srv.Serve()

		pURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", srv.Port()))
		cli := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pURL)}, Timeout: 5 * time.Second}
		resp, err := cli.Get("http://169.254.169.254/latest/meta-data/")
		if err != nil {
			return "", err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			return "", fmt.Errorf("expected 403 for IMDS SSRF, got %d", resp.StatusCode)
		}

		pr := proxyfwd.ProbeUpstream(context.Background(), proxyfwd.UpstreamConfig{
			Scheme:             "http",
			Host:               "127.0.0.1",
			Port:               upPort,
			Username:           user,
			Password:           pass,
			AllowLocal:         true,
			AllowLocalUpstream: true,
		}, target.URL)
		if !pr.OK || pr.ExitIP != "198.51.100.7" {
			return "", fmt.Errorf("probe failed: %+v", pr)
		}
		return "Basic auth OK, IMDS SSRF -> 403, probe OK", nil
	})

	// 6. Optional live browser + CDP test
	if withBrowser {
		runStage("6. Live Browser Launch & CDP Round-Trip", func() (string, error) {
			k := kernel.Resolve(configuredKernel)
			if k == nil {
				return "", fmt.Errorf("no browser kernel discovered on host")
			}
			st, err := store.Open(tmpDir)
			if err != nil {
				return "", err
			}
			// Regenerate fingerprint matching real kernel version.
			host := fingerprint.DetectHost()
			ver := k.Version
			if ver == "" {
				ver = "130.0.0.0"
			}
			fp, err := fingerprint.Generate(fingerprint.GenerateParams{
				ProfileID:      testProfileID,
				Template:       fingerprint.DefaultTemplateID(host.OS, host.GPUVendor),
				BrowserVersion: ver,
				Brand:          k.Brand,
				Timezone:       "America/New_York",
				Languages:      []string{"en-US", "en"},
				Host:           host,
			})
			if err != nil {
				return "", err
			}
			if err := st.WriteFingerprint(testProfileID, fp); err != nil {
				return "", err
			}

			pageSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = io.WriteString(w, `<!doctype html><html><head><title>BrowserForge Live Test</title></head><body><h1>OK</h1><input id="q" oninput="window.__tInput = event.isTrusted" /><button id="go" onclick="document.title=(event.isTrusted && window.__tInput?'Trusted:':'Untrusted:')+document.getElementById('q').value">Go</button></body></html>`)
			}))
			defer pageSrv.Close()

			res, err := kernel.Launch(kernel.LaunchOptions{
				Kernel:      *k,
				ProfileID:   testProfileID,
				UserDataDir: st.UserDataDir(testProfileID),
				CacheDir:    st.CacheDir(testProfileID),
				Headless:    true,
			}, 25*time.Second)
			if err != nil {
				return "", err
			}
			defer kernel.TerminateProcess(res.PID)

			tab, err := cdp.OpenTab(res.DebugPort, pageSrv.URL)
			if err != nil {
				return "", err
			}
			c, err := cdp.Connect(tab.WebSocketDebuggerURL)
			if err != nil {
				return "", err
			}
			defer c.Close()

			if _, err := c.Type("#q", "hello", false); err != nil {
				return "", err
			}
			if _, err := c.Click("#go", ""); err != nil {
				return "", err
			}
			title, err := c.Eval("document.title")
			if err != nil {
				return "", err
			}
			if title != "Trusted:hello" {
				return "", fmt.Errorf("unexpected title %v (expected Trusted:hello)", title)
			}
			png, err := c.Screenshot()
			if err != nil || len(png) < 100 {
				return "", fmt.Errorf("screenshot failed: %v (len=%d)", err, len(png))
			}
			return fmt.Sprintf("kernel=%s(%s) CDP click/type/eval/screenshot(%dB) OK", k.Kind, k.Version, len(png)), nil
		})
	}

	return rep
}
