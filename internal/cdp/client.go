package cdp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

type TabInfo struct {
	ID                   string `json:"id"`
	Type                 string `json:"type"`
	Title                string `json:"title"`
	URL                  string `json:"url"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

type Client struct {
	ws        *WSConn
	msgID     atomic.Int64
	cursorX   float64
	cursorY   float64
	hasCursor bool
}

// SetCursor seeds the starting pointer coordinates for humanized mouse movements.
func (c *Client) SetCursor(x, y float64) {
	c.cursorX = x
	c.cursorY = y
	c.hasCursor = true
}

// Cursor returns the latest pointer coordinates after mouse actions.
func (c *Client) Cursor() (float64, float64, bool) {
	return c.cursorX, c.cursorY, c.hasCursor
}

func Connect(wsURL string) (*Client, error) {
	ws, err := DialWS(wsURL, 10*time.Second)
	if err != nil {
		return nil, err
	}
	return &Client{ws: ws}, nil
}

func (c *Client) Close() error {
	return c.ws.Close()
}

type rpcRequest struct {
	ID     int64          `json:"id"`
	Method string         `json:"method"`
	Params map[string]any `json:"params,omitempty"`
}

type rpcResponse struct {
	ID     int64           `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Call sends a CDP method request and waits for the matching response ID.
func (c *Client) Call(method string, params map[string]any, timeout time.Duration) (json.RawMessage, error) {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	id := c.msgID.Add(1)
	req := rpcRequest{ID: id, Method: method, Params: params}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if err := c.ws.WriteText(payload); err != nil {
		return nil, err
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		rem := time.Until(deadline)
		if rem <= 0 {
			break
		}
		raw, err := c.ws.ReadText(rem)
		if err != nil {
			return nil, err
		}
		var resp rpcResponse
		if err := json.Unmarshal(raw, &resp); err != nil {
			continue
		}
		if resp.ID != id {
			// Skip async CDP events.
			continue
		}
		if resp.Error != nil {
			return nil, fmt.Errorf("CDP %s error %d: %s", method, resp.Error.Code, resp.Error.Message)
		}
		return resp.Result, nil
	}
	return nil, fmt.Errorf("CDP %s timed out", method)
}

// ListTabs lists open page targets from Chromium DevTools HTTP endpoint.
func ListTabs(debugPort int) ([]TabInfo, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/json/list", debugPort))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}
	var all []TabInfo
	if err := json.Unmarshal(body, &all); err != nil {
		return nil, err
	}
	var pages []TabInfo
	for _, t := range all {
		if t.Type == "page" && t.WebSocketDebuggerURL != "" {
			pages = append(pages, t)
		}
	}
	return pages, nil
}

// ResolveTab selects a tab by ID, or returns the first page tab if tabID is empty.
func ResolveTab(debugPort int, tabID string) (*TabInfo, error) {
	tabs, err := ListTabs(debugPort)
	if err != nil {
		return nil, err
	}
	if len(tabs) == 0 {
		return nil, errors.New("no active page tabs found")
	}
	if tabID == "" {
		return &tabs[0], nil
	}
	for i := range tabs {
		if tabs[i].ID == tabID || strings.HasPrefix(tabs[i].ID, tabID) {
			return &tabs[i], nil
		}
	}
	return nil, fmt.Errorf("tab %q not found", tabID)
}

// OpenTab creates a new blank tab via PUT /json/new and navigates via CDP Page.navigate.
func OpenTab(debugPort int, targetURL string) (*TabInfo, error) {
	client := &http.Client{Timeout: 8 * time.Second}
	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("http://127.0.0.1:%d/json/new", debugPort), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("PUT /json/new failed: HTTP %d", resp.StatusCode)
	}
	var tab TabInfo
	if err := json.Unmarshal(body, &tab); err != nil {
		return nil, err
	}
	if tab.WebSocketDebuggerURL == "" {
		return nil, errors.New("new tab missing webSocketDebuggerUrl")
	}

	if targetURL != "" && targetURL != "about:blank" {
		c, err := Connect(tab.WebSocketDebuggerURL)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		_, _ = c.Call("Page.enable", nil, 5*time.Second)
		if _, err := c.Call("Page.navigate", map[string]any{"url": targetURL}, 15*time.Second); err != nil {
			return nil, err
		}
		// Wait for navigation off about:blank and document.readyState === 'complete'.
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			val, err := c.Eval(`({href: location.href, ready: document.readyState, title: document.title})`)
			if err == nil {
				if m, ok := val.(map[string]any); ok {
					href, _ := m["href"].(string)
					ready, _ := m["ready"].(string)
					title, _ := m["title"].(string)
					if href != "" && href != "about:blank" && (ready == "complete" || ready == "interactive") {
						tab.URL = href
						tab.Title = title
						if ready == "complete" {
							break
						}
					}
				}
			}
			time.Sleep(150 * time.Millisecond)
		}
	}
	return &tab, nil
}

// Eval evaluates a JS expression with awaitPromise and returnByValue.
func (c *Client) Eval(expr string) (any, error) {
	raw, err := c.Call("Runtime.evaluate", map[string]any{
		"expression":    expr,
		"awaitPromise":  true,
		"returnByValue": true,
	}, 15*time.Second)
	if err != nil {
		return nil, err
	}
	var out struct {
		Result struct {
			Type        string `json:"type"`
			Value       any    `json:"value"`
			Description string `json:"description"`
		} `json:"result"`
		ExceptionDetails *struct {
			Text      string `json:"text"`
			Exception *struct {
				Description string `json:"description"`
			} `json:"exception"`
		} `json:"exceptionDetails"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if out.ExceptionDetails != nil {
		msg := out.ExceptionDetails.Text
		if out.ExceptionDetails.Exception != nil && out.ExceptionDetails.Exception.Description != "" {
			msg = out.ExceptionDetails.Exception.Description
		}
		return nil, fmt.Errorf("JS exception: %s", msg)
	}
	if out.Result.Value == nil && out.Result.Description != "" {
		return out.Result.Description, nil
	}
	return out.Result.Value, nil
}

// Snapshot extracts page title, URL, visible text, and interactive elements with CSS selectors.
func (c *Client) Snapshot() (any, error) {
	const script = `(() => {
  const cssPath = (el) => {
    if (el.id) return '#' + CSS.escape(el.id);
    const name = el.getAttribute('name');
    if (name) return el.tagName.toLowerCase() + '[name="' + name.replace(/"/g, '\\"') + '"]';
    const parts = [];
    let cur = el;
    while (cur && cur.nodeType === 1 && parts.length < 4) {
      let sel = cur.tagName.toLowerCase();
      if (cur.id) { parts.unshift('#' + CSS.escape(cur.id)); break; }
      const parent = cur.parentElement;
      if (parent) {
        const siblings = Array.from(parent.children).filter(c => c.tagName === cur.tagName);
        if (siblings.length > 1) sel += ':nth-of-type(' + (siblings.indexOf(cur) + 1) + ')';
      }
      parts.unshift(sel);
      cur = parent;
    }
    return parts.join(' > ');
  };
  const els = Array.from(document.querySelectorAll('a,button,input,textarea,select,[role="button"]')).slice(0, 60).map((el, i) => ({
    index: i,
    tag: el.tagName.toLowerCase(),
    type: el.getAttribute('type') || '',
    text: (el.innerText || el.value || el.getAttribute('aria-label') || el.getAttribute('placeholder') || '').trim().slice(0, 100),
    selector: cssPath(el),
  }));
  return {
    url: location.href,
    title: document.title,
    text: (document.body ? document.body.innerText : '').trim().slice(0, 4000),
    elements: els,
  };
})()`
	return c.Eval(script)
}

// Click clicks an element matched by CSS selector or visible text using
// hardware-level trusted Input.dispatchMouseEvent (mouseMoved -> mousePressed -> mouseReleased).
func (c *Client) Click(selector, text string) (any, error) {
	selJSON, _ := json.Marshal(selector)
	txtJSON, _ := json.Marshal(text)
	// Step 1: Locate element and scroll into viewport center.
	scrollScript := fmt.Sprintf(`(() => {
  const sel = %s, txt = %s;
  let el = sel ? document.querySelector(sel) : null;
  if (!el && txt) {
    const cands = Array.from(document.querySelectorAll('button,a,input[type="submit"],input[type="button"],[role="button"]'));
    el = cands.find(e => ((e.innerText || e.value || '').trim()).includes(txt));
  }
  if (!el) throw new Error('element not found');
  el.scrollIntoView({ behavior: 'instant', block: 'center', inline: 'center' });
  return true;
})()`, selJSON, txtJSON)
	if _, err := c.Eval(scrollScript); err != nil {
		return nil, err
	}
	_, _ = c.Call("Page.bringToFront", nil, 15*time.Second)
	time.Sleep(60 * time.Millisecond)

	// Step 2: Re-measure exact element bounding box & viewport after scroll settles.
	rectScript := fmt.Sprintf(`(() => {
  const sel = %s, txt = %s;
  let el = sel ? document.querySelector(sel) : null;
  if (!el && txt) {
    const cands = Array.from(document.querySelectorAll('button,a,input[type="submit"],input[type="button"],[role="button"]'));
    el = cands.find(e => ((e.innerText || e.value || '').trim()).includes(txt));
  }
  if (!el) throw new Error('element not found');
  const r = el.getBoundingClientRect();
  if (r.width <= 0 || r.height <= 0) throw new Error('element has zero size');
  return {
    left: r.left, top: r.top, width: r.width, height: r.height,
    vw: window.innerWidth || 1280, vh: window.innerHeight || 800,
    tag: el.tagName.toLowerCase(),
    text: (el.innerText || el.value || '').trim().slice(0, 100)
  };
})()`, selJSON, txtJSON)
	val, err := c.Eval(rectScript)
	if err != nil {
		return nil, err
	}
	m, ok := val.(map[string]any)
	if !ok {
		return nil, errors.New("failed to resolve element bounding box")
	}
	left, _ := m["left"].(float64)
	top, _ := m["top"].(float64)
	width, _ := m["width"].(float64)
	height, _ := m["height"].(float64)
	vw, _ := m["vw"].(float64)
	vh, _ := m["vh"].(float64)

	// Pick randomized landing point inside inner 30%..70% of element rect.
	x, y := PickHumanLandingPoint(left, top, width, height, vw, vh)

	// Step 3: Humanized cubic Bezier mouse trajectory -> settle -> randomized dwell press/release.
	steps, err := c.moveMouseHumanized(x, y, vw, vh)
	if err != nil {
		return nil, err
	}
	time.Sleep(time.Duration(randRangeInt(35, 95)) * time.Millisecond)

	dwellMS := randRangeInt(55, 135)
	if _, err := c.Call("Input.dispatchMouseEvent", map[string]any{
		"type":        "mousePressed",
		"x":           x,
		"y":           y,
		"button":      "left",
		"buttons":     1,
		"clickCount":  1,
		"pointerType": "mouse",
	}, 15*time.Second); err != nil {
		return nil, err
	}
	time.Sleep(time.Duration(dwellMS) * time.Millisecond)
	if _, err := c.Call("Input.dispatchMouseEvent", map[string]any{
		"type":        "mouseReleased",
		"x":           x,
		"y":           y,
		"button":      "left",
		"buttons":     0,
		"clickCount":  1,
		"pointerType": "mouse",
	}, 15*time.Second); err != nil {
		return nil, err
	}
	return map[string]any{
		"clicked":  true,
		"trusted":  true,
		"x":        x,
		"y":        y,
		"steps":    steps,
		"dwell_ms": dwellMS,
		"tag":      m["tag"],
		"text":     m["text"],
	}, nil
}

func asciiKeyMeta(r rune) (code string, vk int) {
	switch {
	case r >= 'a' && r <= 'z':
		u := r - 'a' + 'A'
		return fmt.Sprintf("Key%c", u), int(u)
	case r >= 'A' && r <= 'Z':
		return fmt.Sprintf("Key%c", r), int(r)
	case r >= '0' && r <= '9':
		return fmt.Sprintf("Digit%c", r), int(r)
	case r == ' ':
		return "Space", 32
	case r == '-':
		return "Minus", 189
	case r == '=':
		return "Equal", 187
	case r == '.':
		return "Period", 190
	case r == ',':
		return "Comma", 188
	case r == '/':
		return "Slash", 191
	default:
		return "", int(r)
	}
}

// Type focuses selector via a real hardware Bezier click, clears any existing text via Ctrl+A + Backspace,
// and types text character-by-character with hardware-level trusted Input.dispatchKeyEvent / Input.insertText.
func (c *Client) Type(selector, text string, submit bool) (any, error) {
	if strings.TrimSpace(selector) == "" {
		return nil, errors.New("--selector is required")
	}
	// Step 1: Hardware click to focus input naturally (continuous Bezier trajectory).
	if _, err := c.Click(selector, ""); err != nil {
		return nil, err
	}
	time.Sleep(time.Duration(randRangeInt(60, 130)) * time.Millisecond)

	// Ensure focus and check whether input already contains text that should be cleared.
	selJSON, _ := json.Marshal(selector)
	hasExistingVal, err := c.Eval(fmt.Sprintf(`(() => {
  const el = document.querySelector(%s);
  if (!el) throw new Error('input element not found');
  if (document.activeElement !== el) el.focus();
  return !!(el.value && el.value.length > 0);
})()`, selJSON))
	if err != nil {
		return nil, err
	}
	if hasVal, _ := hasExistingVal.(bool); hasVal {
		// Hardware Ctrl+A then Backspace to clear existing value cleanly.
		_, _ = c.Call("Input.dispatchKeyEvent", map[string]any{
			"type":                  "keyDown",
			"modifiers":             2, // Ctrl
			"key":                   "a",
			"code":                  "KeyA",
			"windowsVirtualKeyCode": 65,
			"nativeVirtualKeyCode":  65,
		}, 15*time.Second)
		_, _ = c.Call("Input.dispatchKeyEvent", map[string]any{
			"type":                  "keyUp",
			"modifiers":             2,
			"key":                   "a",
			"code":                  "KeyA",
			"windowsVirtualKeyCode": 65,
			"nativeVirtualKeyCode":  65,
		}, 15*time.Second)
		time.Sleep(time.Duration(randRangeInt(30, 70)) * time.Millisecond)
		_, _ = c.Press("Backspace")
		time.Sleep(time.Duration(randRangeInt(50, 110)) * time.Millisecond)
	}

	// Step 2: Type character-by-character using trusted hardware key events.
	runes := []rune(text)
	for i, r := range runes {
		if r >= 0x20 && r <= 0x7e {
			ch := string(r)
			code, vk := asciiKeyMeta(r)
			down := map[string]any{
				"type":                  "keyDown",
				"key":                   ch,
				"text":                  ch,
				"unmodifiedText":        ch,
				"windowsVirtualKeyCode": vk,
				"nativeVirtualKeyCode":  vk,
			}
			up := map[string]any{
				"type":                  "keyUp",
				"key":                   ch,
				"windowsVirtualKeyCode": vk,
				"nativeVirtualKeyCode":  vk,
			}
			if code != "" {
				down["code"] = code
				up["code"] = code
			}
			if _, err := c.Call("Input.dispatchKeyEvent", down, 15*time.Second); err != nil {
				return nil, err
			}
			time.Sleep(time.Duration(randRangeInt(15, 42)) * time.Millisecond)
			if _, err := c.Call("Input.dispatchKeyEvent", up, 15*time.Second); err != nil {
				return nil, err
			}
		} else {
			if _, err := c.Call("Input.insertText", map[string]any{"text": string(r)}, 15*time.Second); err != nil {
				return nil, err
			}
		}
		if i < len(runes)-1 {
			time.Sleep(time.Duration(randRangeInt(40, 115)) * time.Millisecond)
		}
	}

	// Step 3: Optional hardware Enter submission.
	if submit {
		time.Sleep(time.Duration(randRangeInt(120, 240)) * time.Millisecond)
		if _, err := c.Press("Enter"); err != nil {
			return nil, err
		}
	}

	return map[string]any{
		"typed":       true,
		"trusted":     true,
		"submitted":   submit,
		"valueLength": len(runes),
	}, nil
}

// Screenshot captures a PNG screenshot of the current page.
func (c *Client) Screenshot() ([]byte, error) {
	raw, err := c.Call("Page.captureScreenshot", map[string]any{"format": "png"}, 15*time.Second)
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

type CookieItem struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	Secure   bool    `json:"secure"`
	HttpOnly bool    `json:"httpOnly"`
	Expires  float64 `json:"expires"`
}

// GetCookies retrieves browser cookies, redacting values unless includeValues is true.
func (c *Client) GetCookies(includeValues bool) ([]CookieItem, error) {
	raw, err := c.Call("Network.getAllCookies", nil, 10*time.Second)
	if err != nil {
		return nil, err
	}
	var out struct {
		Cookies []CookieItem `json:"cookies"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if !includeValues {
		for i := range out.Cookies {
			out.Cookies[i].Value = "***REDACTED***"
		}
	}
	return out.Cookies, nil
}
