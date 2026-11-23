package proxyfwd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type ProbeResult struct {
	OK        bool   `json:"ok"`
	LatencyMS int64  `json:"latency_ms"`
	ExitIP    string `json:"exit_ip,omitempty"`
	Country   string `json:"country,omitempty"`
	Timezone  string `json:"timezone,omitempty"`
	Error     string `json:"error,omitempty"`
}

// ProbeUpstream tests connectivity and exit IP metadata through an upstream proxy with a 1 MiB response cap.
func ProbeUpstream(ctx context.Context, cfg UpstreamConfig, probeURL string) ProbeResult {
	if probeURL == "" {
		probeURL = "https://ipwho.is/"
	}
	start := time.Now()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return DialUpstreamThrough(ctx, cfg, addr)
		},
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Transport: tr,
		Timeout:   15 * time.Second,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return ProbeResult{OK: false, Error: err.Error()}
	}
	req.Header.Set("User-Agent", "BrowserForge-Probe/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return ProbeResult{OK: false, LatencyMS: time.Since(start).Milliseconds(), Error: err.Error()}
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, MaxProbeBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return ProbeResult{OK: false, LatencyMS: time.Since(start).Milliseconds(), Error: err.Error()}
	}
	if len(body) > MaxProbeBytes {
		return ProbeResult{OK: false, LatencyMS: time.Since(start).Milliseconds(), Error: fmt.Sprintf("probe response exceeded %d bytes", MaxProbeBytes)}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ProbeResult{OK: false, LatencyMS: time.Since(start).Milliseconds(), Error: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}

	var parsed struct {
		IP          string `json:"ip"`
		CountryCode string `json:"country_code"`
		Country     string `json:"country"`
		Timezone    any    `json:"timezone"`
	}
	_ = json.Unmarshal(body, &parsed)

	tz := ""
	switch v := parsed.Timezone.(type) {
	case string:
		tz = v
	case map[string]any:
		if id, ok := v["id"].(string); ok {
			tz = id
		}
	}
	country := parsed.CountryCode
	if country == "" {
		country = parsed.Country
	}

	return ProbeResult{
		OK:        true,
		LatencyMS: time.Since(start).Milliseconds(),
		ExitIP:    parsed.IP,
		Country:   country,
		Timezone:  tz,
	}
}
