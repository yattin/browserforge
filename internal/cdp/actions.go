package cdp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CloseTab closes a specific target tab via Chromium DevTools HTTP endpoint.
func CloseTab(debugPort int, tabID string) error {
	if strings.TrimSpace(tabID) == "" {
		return errors.New("tab ID is required")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/json/close/%s", debugPort, tabID))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("close tab failed: HTTP %d (%s)", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// Navigate loads targetURL in the currently attached tab and waits for document completion.
func (c *Client) Navigate(targetURL string, timeout time.Duration) (map[string]any, error) {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	_, _ = c.Call("Page.enable", nil, 5*time.Second)
	if _, err := c.Call("Page.navigate", map[string]any{"url": targetURL}, timeout); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	var last map[string]any
	for time.Now().Before(deadline) {
		val, err := c.Eval(`({url: location.href, ready: document.readyState, title: document.title})`)
		if err == nil {
			if m, ok := val.(map[string]any); ok {
				last = m
				ready, _ := m["ready"].(string)
				href, _ := m["url"].(string)
				if href != "" && (targetURL == "about:blank" || href != "about:blank") && ready == "complete" {
					return m, nil
				}
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	if last != nil {
		return last, nil
	}
	return map[string]any{"url": targetURL}, nil
}

// WaitFor polls the page until selector exists, text appears, or URL contains urlSubstr.
func (c *Client) WaitFor(selector, text, urlSubstr string, timeout time.Duration) (map[string]any, error) {
	if selector == "" && text == "" && urlSubstr == "" {
		return nil, errors.New("provide at least one of --selector, --text, or --url")
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	selJSON, _ := json.Marshal(selector)
	txtJSON, _ := json.Marshal(text)
	urlJSON, _ := json.Marshal(urlSubstr)
	script := fmt.Sprintf(`(() => {
  const sel = %s, txt = %s, u = %s;
  const okSel = !sel || !!document.querySelector(sel);
  const okTxt = !txt || ((document.body ? document.body.innerText : '').includes(txt));
  const okUrl = !u || location.href.includes(u);
  return { matched: okSel && okTxt && okUrl, url: location.href, title: document.title };
})()`, selJSON, txtJSON, urlJSON)

	start := time.Now()
	deadline := start.Add(timeout)
	for time.Now().Before(deadline) {
		val, err := c.Eval(script)
		if err == nil {
			if m, ok := val.(map[string]any); ok {
				if matched, _ := m["matched"].(bool); matched {
					m["elapsed_ms"] = time.Since(start).Milliseconds()
					return m, nil
				}
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	return nil, fmt.Errorf("timed out after %s waiting for condition", timeout)
}

// Scroll scrolls the page by y pixels, to bottom, or into view of selector.
func (c *Client) Scroll(y int, toBottom bool, selector string) (any, error) {
	selJSON, _ := json.Marshal(selector)
	script := fmt.Sprintf(`(() => {
  const sel = %s;
  if (sel) {
    const el = document.querySelector(sel);
    if (!el) throw new Error('element not found: ' + sel);
    el.scrollIntoView({ behavior: 'instant', block: 'center' });
  } else if (%v) {
    window.scrollTo(0, document.body ? document.body.scrollHeight : 100000);
  } else {
    window.scrollBy(0, %d);
  }
  return { scrollX: window.scrollX, scrollY: window.scrollY };
})()`, selJSON, toBottom, y)
	return c.Eval(script)
}

// Hover moves the real pointer along a humanized Bezier curve into selector via Input.dispatchMouseEvent.
func (c *Client) Hover(selector string) (map[string]any, error) {
	if strings.TrimSpace(selector) == "" {
		return nil, errors.New("--selector is required")
	}
	selJSON, _ := json.Marshal(selector)
	script := fmt.Sprintf(`(() => {
  const el = document.querySelector(%s);
  if (!el) throw new Error('element not found');
  el.scrollIntoView({ behavior: 'instant', block: 'center', inline: 'center' });
  const r = el.getBoundingClientRect();
  if (r.width <= 0 || r.height <= 0) throw new Error('element has zero size');
  return { left: r.left, top: r.top, width: r.width, height: r.height, vw: window.innerWidth || 1280, vh: window.innerHeight || 800, tag: el.tagName.toLowerCase() };
})()`, selJSON)
	val, err := c.Eval(script)
	if err != nil {
		return nil, err
	}
	m, ok := val.(map[string]any)
	if !ok {
		return nil, errors.New("failed to resolve element coordinates")
	}
	left, _ := m["left"].(float64)
	top, _ := m["top"].(float64)
	width, _ := m["width"].(float64)
	height, _ := m["height"].(float64)
	vw, _ := m["vw"].(float64)
	vh, _ := m["vh"].(float64)

	x, y := PickHumanLandingPoint(left, top, width, height, vw, vh)
	steps, err := c.moveMouseHumanized(x, y, vw, vh)
	if err != nil {
		return nil, err
	}
	return map[string]any{"hovered": true, "trusted": true, "x": x, "y": y, "steps": steps, "tag": m["tag"]}, nil
}

type keyDef struct {
	key  string
	code string
	vk   int
	text string
}

var namedKeys = map[string]keyDef{
	"enter":      {key: "Enter", code: "Enter", vk: 13, text: "\r"},
	"escape":     {key: "Escape", code: "Escape", vk: 27},
	"esc":        {key: "Escape", code: "Escape", vk: 27},
	"tab":        {key: "Tab", code: "Tab", vk: 9},
	"backspace":  {key: "Backspace", code: "Backspace", vk: 8},
	"delete":     {key: "Delete", code: "Delete", vk: 46},
	"space":      {key: " ", code: "Space", vk: 32, text: " "},
	"arrowup":    {key: "ArrowUp", code: "ArrowUp", vk: 38},
	"arrowdown":  {key: "ArrowDown", code: "ArrowDown", vk: 40},
	"arrowleft":  {key: "ArrowLeft", code: "ArrowLeft", vk: 37},
	"arrowright": {key: "ArrowRight", code: "ArrowRight", vk: 39},
	"home":       {key: "Home", code: "Home", vk: 36},
	"end":        {key: "End", code: "End", vk: 35},
	"pageup":     {key: "PageUp", code: "PageUp", vk: 33},
	"pagedown":   {key: "PageDown", code: "PageDown", vk: 34},
}

// Press dispatches a hardware-level keyDown + keyUp event via Input.dispatchKeyEvent.
func (c *Client) Press(key string) (map[string]any, error) {
	k := strings.TrimSpace(key)
	if k == "" {
		return nil, errors.New("--key is required")
	}
	def, ok := namedKeys[strings.ToLower(k)]
	if !ok {
		runes := []rune(k)
		if len(runes) == 1 {
			def = keyDef{key: k, code: "", vk: int(runes[0]), text: k}
		} else {
			def = keyDef{key: k, code: k}
		}
	}
	downParams := map[string]any{
		"type":                  "keyDown",
		"key":                   def.key,
		"windowsVirtualKeyCode": def.vk,
		"nativeVirtualKeyCode":  def.vk,
	}
	if def.code != "" {
		downParams["code"] = def.code
	}
	if def.text != "" {
		downParams["text"] = def.text
		downParams["unmodifiedText"] = def.text
	}
	if _, err := c.Call("Input.dispatchKeyEvent", downParams, 15*time.Second); err != nil {
		return nil, err
	}
	time.Sleep(time.Duration(randRangeInt(20, 55)) * time.Millisecond)
	upParams := map[string]any{
		"type":                  "keyUp",
		"key":                   def.key,
		"windowsVirtualKeyCode": def.vk,
		"nativeVirtualKeyCode":  def.vk,
	}
	if def.code != "" {
		upParams["code"] = def.code
	}
	if _, err := c.Call("Input.dispatchKeyEvent", upParams, 15*time.Second); err != nil {
		return nil, err
	}
	return map[string]any{"pressed": true, "trusted": true, "key": def.key}, nil
}

// GetHTML returns the outerHTML of the document or a matching CSS selector.
func (c *Client) GetHTML(selector string) (string, error) {
	var script string
	if strings.TrimSpace(selector) == "" {
		script = `document.documentElement ? document.documentElement.outerHTML : ''`
	} else {
		selJSON, _ := json.Marshal(selector)
		script = fmt.Sprintf(`(() => { const el = document.querySelector(%s); if (!el) throw new Error('element not found'); return el.outerHTML; })()`, selJSON)
	}
	val, err := c.Eval(script)
	if err != nil {
		return "", err
	}
	s, _ := val.(string)
	return s, nil
}

// PrintPDF exports the current page to PDF via Page.printToPDF.
func (c *Client) PrintPDF() ([]byte, error) {
	raw, err := c.Call("Page.printToPDF", map[string]any{
		"printBackground": true,
	}, 20*time.Second)
	if err != nil {
		return nil, err
	}
	var out struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Data)
}

// SetCookies imports cookies into the browser via Network.setCookies.
func (c *Client) SetCookies(cookies []CookieItem) (int, error) {
	var payload []map[string]any
	for _, ck := range cookies {
		if ck.Name == "" || ck.Value == "***REDACTED***" {
			continue
		}
		item := map[string]any{
			"name":     ck.Name,
			"value":    ck.Value,
			"domain":   ck.Domain,
			"path":     ck.Path,
			"secure":   ck.Secure,
			"httpOnly": ck.HttpOnly,
		}
		if ck.Expires > 0 {
			item["expires"] = ck.Expires
		}
		payload = append(payload, item)
	}
	if len(payload) == 0 {
		return 0, errors.New("no valid (non-redacted) cookies to import")
	}
	if _, err := c.Call("Network.setCookies", map[string]any{"cookies": payload}, 10*time.Second); err != nil {
		return 0, err
	}
	return len(payload), nil
}

type cdpEventEnvelope struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// listenEvents reads incoming CDP events for duration and dispatches them to handler.
func (c *Client) listenEvents(duration time.Duration, handler func(method string, params json.RawMessage)) {
	if duration <= 0 {
		duration = 5 * time.Second
	}
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		rem := time.Until(deadline)
		if rem <= 0 {
			break
		}
		raw, err := c.ws.ReadText(rem)
		if err != nil {
			break
		}
		var env cdpEventEnvelope
		if json.Unmarshal(raw, &env) == nil && env.Method != "" {
			handler(env.Method, env.Params)
		}
	}
}

type ConsoleEntry struct {
	Kind      string `json:"kind"` // log, warn, error, debug, exception
	Text      string `json:"text"`
	Timestamp string `json:"timestamp"`
}

// CaptureConsole enables Runtime.enable and captures console messages & uncaught exceptions for duration.
func (c *Client) CaptureConsole(duration time.Duration) ([]ConsoleEntry, error) {
	if _, err := c.Call("Runtime.enable", nil, 5*time.Second); err != nil {
		return nil, err
	}
	var entries []ConsoleEntry
	c.listenEvents(duration, func(method string, params json.RawMessage) {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		switch method {
		case "Runtime.consoleAPICalled":
			var ev struct {
				Type string `json:"type"`
				Args []struct {
					Type        string `json:"type"`
					Value       any    `json:"value"`
					Description string `json:"description"`
				} `json:"args"`
			}
			if json.Unmarshal(params, &ev) == nil {
				parts := make([]string, 0, len(ev.Args))
				for _, a := range ev.Args {
					if a.Value != nil {
						parts = append(parts, fmt.Sprint(a.Value))
					} else if a.Description != "" {
						parts = append(parts, a.Description)
					} else {
						parts = append(parts, a.Type)
					}
				}
				entries = append(entries, ConsoleEntry{
					Kind:      ev.Type,
					Text:      strings.Join(parts, " "),
					Timestamp: now,
				})
			}
		case "Runtime.exceptionThrown":
			var ev struct {
				ExceptionDetails struct {
					Text      string `json:"text"`
					Exception *struct {
						Description string `json:"description"`
					} `json:"exception"`
				} `json:"exceptionDetails"`
			}
			if json.Unmarshal(params, &ev) == nil {
				txt := ev.ExceptionDetails.Text
				if ev.ExceptionDetails.Exception != nil && ev.ExceptionDetails.Exception.Description != "" {
					txt = ev.ExceptionDetails.Exception.Description
				}
				entries = append(entries, ConsoleEntry{
					Kind:      "exception",
					Text:      txt,
					Timestamp: now,
				})
			}
		}
	})
	return entries, nil
}

type NetworkEntry struct {
	RequestID string `json:"request_id"`
	Method    string `json:"method"`
	URL       string `json:"url"`
	Status    int    `json:"status,omitempty"`
	MimeType  string `json:"mime_type,omitempty"`
	Failed    bool   `json:"failed,omitempty"`
	ErrorText string `json:"error_text,omitempty"`
}

// CaptureNetwork enables Network.enable and records network requests/responses for duration.
func (c *Client) CaptureNetwork(duration time.Duration, filter string) ([]NetworkEntry, error) {
	if _, err := c.Call("Network.enable", nil, 5*time.Second); err != nil {
		return nil, err
	}
	byID := map[string]*NetworkEntry{}
	var order []string
	filterLower := strings.ToLower(strings.TrimSpace(filter))

	c.listenEvents(duration, func(method string, params json.RawMessage) {
		switch method {
		case "Network.requestWillBeSent":
			var ev struct {
				RequestID string `json:"requestId"`
				Request   struct {
					URL    string `json:"url"`
					Method string `json:"method"`
				} `json:"request"`
			}
			if json.Unmarshal(params, &ev) == nil && ev.RequestID != "" {
				if filterLower != "" && !strings.Contains(strings.ToLower(ev.Request.URL), filterLower) {
					return
				}
				if _, exists := byID[ev.RequestID]; !exists {
					order = append(order, ev.RequestID)
				}
				byID[ev.RequestID] = &NetworkEntry{
					RequestID: ev.RequestID,
					Method:    ev.Request.Method,
					URL:       ev.Request.URL,
				}
			}
		case "Network.responseReceived":
			var ev struct {
				RequestID string `json:"requestId"`
				Response  struct {
					URL      string `json:"url"`
					Status   int    `json:"status"`
					MimeType string `json:"mimeType"`
				} `json:"response"`
			}
			if json.Unmarshal(params, &ev) == nil {
				if entry, ok := byID[ev.RequestID]; ok {
					entry.Status = ev.Response.Status
					entry.MimeType = ev.Response.MimeType
				}
			}
		case "Network.loadingFailed":
			var ev struct {
				RequestID string `json:"requestId"`
				ErrorText string `json:"errorText"`
			}
			if json.Unmarshal(params, &ev) == nil {
				if entry, ok := byID[ev.RequestID]; ok {
					entry.Failed = true
					entry.ErrorText = ev.ErrorText
				}
			}
		}
	})

	out := make([]NetworkEntry, 0, len(order))
	for _, id := range order {
		if e, ok := byID[id]; ok {
			out = append(out, *e)
		}
	}
	return out, nil
}
