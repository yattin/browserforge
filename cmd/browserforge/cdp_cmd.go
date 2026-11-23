package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"browserforge/internal/cdp"
	"browserforge/internal/common"
	"browserforge/internal/store"
)

func cmdCDP(dataDir string, jsonOut bool, args []string) error {
	if len(args) < 2 {
		return errors.New("usage: browserforge cdp <tabs|open|navigate|close-tab|wait|snapshot|click|type|scroll|hover|press|eval|html|screenshot|pdf|cookies|export-cookies|set-cookies|console|network> <profile> [flags]")
	}
	st, err := store.Open(dataDir)
	if err != nil {
		return err
	}
	action := args[0]
	profileRef := args[1]
	rest := args[2:]

	rt, err := resolveRunningRuntime(st, profileRef)
	if err != nil {
		return err
	}
	port := rt.DebugPort

	switch action {
	case "tabs":
		tabs, err := cdp.ListTabs(port)
		if err != nil {
			return err
		}
		if jsonOut {
			return common.PrintJSON(tabs)
		}
		for _, t := range tabs {
			fmt.Printf("%s  %-30s  %s\n", t.ID, truncate(t.Title, 30), t.URL)
		}
		return nil

	case "open":
		if len(rest) < 1 {
			return errors.New("usage: browserforge cdp open <profile> <url>")
		}
		tab, err := cdp.OpenTab(port, rest[0])
		if err != nil {
			return err
		}
		if jsonOut {
			return common.PrintJSON(tab)
		}
		fmt.Printf("Opened tab %s -> %s (%s)\n", tab.ID, tab.URL, tab.Title)
		return nil

	case "navigate":
		fs := flag.NewFlagSet("cdp navigate", flag.ContinueOnError)
		tabID := fs.String("tab", "", "target tab ID")
		timeout := fs.Duration("timeout", 15*time.Second, "load timeout")
		if err := parseFlagsFlexible(fs, rest); err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return errors.New("usage: browserforge cdp navigate <profile> [--tab <id>] <url>")
		}
		tab, err := cdp.ResolveTab(port, *tabID)
		if err != nil {
			return err
		}
		c, err := cdp.Connect(tab.WebSocketDebuggerURL)
		if err != nil {
			return err
		}
		defer c.Close()
		res, err := c.Navigate(fs.Arg(0), *timeout)
		if err != nil {
			return err
		}
		if jsonOut {
			return common.PrintJSON(res)
		}
		fmt.Printf("Navigated -> %v (%v)\n", res["url"], res["title"])
		return nil

	case "close-tab":
		fs := flag.NewFlagSet("cdp close-tab", flag.ContinueOnError)
		tabID := fs.String("tab", "", "tab ID to close")
		if err := parseFlagsFlexible(fs, rest); err != nil {
			return err
		}
		id := *tabID
		if id == "" && fs.NArg() > 0 {
			id = fs.Arg(0)
		}
		tab, err := cdp.ResolveTab(port, id)
		if err != nil {
			return err
		}
		if err := cdp.CloseTab(port, tab.ID); err != nil {
			return err
		}
		if jsonOut {
			return common.PrintJSON(map[string]any{"ok": true, "closed": tab.ID})
		}
		fmt.Printf("Closed tab %s\n", tab.ID)
		return nil

	case "wait":
		fs := flag.NewFlagSet("cdp wait", flag.ContinueOnError)
		tabID := fs.String("tab", "", "target tab ID")
		selector := fs.String("selector", "", "wait for CSS selector")
		text := fs.String("text", "", "wait for text in body")
		urlSub := fs.String("url", "", "wait for URL substring")
		timeout := fs.Duration("timeout", 15*time.Second, "wait timeout")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		tab, err := cdp.ResolveTab(port, *tabID)
		if err != nil {
			return err
		}
		c, err := cdp.Connect(tab.WebSocketDebuggerURL)
		if err != nil {
			return err
		}
		defer c.Close()
		res, err := c.WaitFor(*selector, *text, *urlSub, *timeout)
		if err != nil {
			return err
		}
		if jsonOut {
			return common.PrintJSON(res)
		}
		fmt.Printf("Matched in %vms (%v)\n", res["elapsed_ms"], res["url"])
		return nil

	case "snapshot":
		fs := flag.NewFlagSet("cdp snapshot", flag.ContinueOnError)
		tabID := fs.String("tab", "", "target tab ID")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		tab, err := cdp.ResolveTab(port, *tabID)
		if err != nil {
			return err
		}
		c, err := cdp.Connect(tab.WebSocketDebuggerURL)
		if err != nil {
			return err
		}
		defer c.Close()
		snap, err := c.Snapshot()
		if err != nil {
			return err
		}
		return common.PrintJSON(snap)

	case "click":
		fs := flag.NewFlagSet("cdp click", flag.ContinueOnError)
		tabID := fs.String("tab", "", "target tab ID")
		selector := fs.String("selector", "", "CSS selector")
		text := fs.String("text", "", "visible button/link text")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *selector == "" && *text == "" {
			return errors.New("provide --selector or --text")
		}
		tab, err := cdp.ResolveTab(port, *tabID)
		if err != nil {
			return err
		}
		c, err := cdp.Connect(tab.WebSocketDebuggerURL)
		if err != nil {
			return err
		}
		defer c.Close()
		if rt.HasMousePos {
			c.SetCursor(rt.LastMouseX, rt.LastMouseY)
		}
		res, err := c.Click(*selector, *text)
		if err != nil {
			return err
		}
		if cx, cy, ok := c.Cursor(); ok {
			rt.LastMouseX, rt.LastMouseY, rt.HasMousePos = cx, cy, true
			_ = st.SaveRuntime(*rt)
		}
		if jsonOut {
			return common.PrintJSON(res)
		}
		fmt.Printf("Clicked: %v\n", res)
		return nil

	case "type":
		fs := flag.NewFlagSet("cdp type", flag.ContinueOnError)
		tabID := fs.String("tab", "", "target tab ID")
		selector := fs.String("selector", "", "CSS selector")
		text := fs.String("text", "", "text to input")
		submit := fs.Bool("submit", false, "submit form / press Enter")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *selector == "" {
			return errors.New("--selector is required")
		}
		tab, err := cdp.ResolveTab(port, *tabID)
		if err != nil {
			return err
		}
		c, err := cdp.Connect(tab.WebSocketDebuggerURL)
		if err != nil {
			return err
		}
		defer c.Close()
		if rt.HasMousePos {
			c.SetCursor(rt.LastMouseX, rt.LastMouseY)
		}
		res, err := c.Type(*selector, *text, *submit)
		if err != nil {
			return err
		}
		if cx, cy, ok := c.Cursor(); ok {
			rt.LastMouseX, rt.LastMouseY, rt.HasMousePos = cx, cy, true
			_ = st.SaveRuntime(*rt)
		}
		if jsonOut {
			return common.PrintJSON(res)
		}
		fmt.Printf("Typed: %v\n", res)
		return nil

	case "scroll":
		fs := flag.NewFlagSet("cdp scroll", flag.ContinueOnError)
		tabID := fs.String("tab", "", "target tab ID")
		y := fs.Int("y", 600, "vertical scroll offset in px")
		toBottom := fs.Bool("to-bottom", false, "scroll to bottom of page")
		selector := fs.String("selector", "", "scroll element into view")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		tab, err := cdp.ResolveTab(port, *tabID)
		if err != nil {
			return err
		}
		c, err := cdp.Connect(tab.WebSocketDebuggerURL)
		if err != nil {
			return err
		}
		defer c.Close()
		res, err := c.Scroll(*y, *toBottom, *selector)
		if err != nil {
			return err
		}
		if jsonOut {
			return common.PrintJSON(res)
		}
		fmt.Printf("Scrolled: %v\n", res)
		return nil

	case "hover":
		fs := flag.NewFlagSet("cdp hover", flag.ContinueOnError)
		tabID := fs.String("tab", "", "target tab ID")
		selector := fs.String("selector", "", "CSS selector")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		tab, err := cdp.ResolveTab(port, *tabID)
		if err != nil {
			return err
		}
		c, err := cdp.Connect(tab.WebSocketDebuggerURL)
		if err != nil {
			return err
		}
		defer c.Close()
		if rt.HasMousePos {
			c.SetCursor(rt.LastMouseX, rt.LastMouseY)
		}
		res, err := c.Hover(*selector)
		if err != nil {
			return err
		}
		if cx, cy, ok := c.Cursor(); ok {
			rt.LastMouseX, rt.LastMouseY, rt.HasMousePos = cx, cy, true
			_ = st.SaveRuntime(*rt)
		}
		if jsonOut {
			return common.PrintJSON(res)
		}
		fmt.Printf("Hovered: %v\n", res)
		return nil

	case "press":
		fs := flag.NewFlagSet("cdp press", flag.ContinueOnError)
		tabID := fs.String("tab", "", "target tab ID")
		key := fs.String("key", "", "key name e.g. Enter, Escape, Tab, ArrowDown")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		tab, err := cdp.ResolveTab(port, *tabID)
		if err != nil {
			return err
		}
		c, err := cdp.Connect(tab.WebSocketDebuggerURL)
		if err != nil {
			return err
		}
		defer c.Close()
		res, err := c.Press(*key)
		if err != nil {
			return err
		}
		if jsonOut {
			return common.PrintJSON(res)
		}
		fmt.Printf("Pressed: %v\n", res["key"])
		return nil

	case "eval":
		fs := flag.NewFlagSet("cdp eval", flag.ContinueOnError)
		tabID := fs.String("tab", "", "target tab ID")
		if err := parseFlagsFlexible(fs, rest); err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return errors.New("usage: browserforge cdp eval <profile> [--tab <id>] <js-expression>")
		}
		expr := strings.Join(fs.Args(), " ")
		tab, err := cdp.ResolveTab(port, *tabID)
		if err != nil {
			return err
		}
		c, err := cdp.Connect(tab.WebSocketDebuggerURL)
		if err != nil {
			return err
		}
		defer c.Close()
		val, err := c.Eval(expr)
		if err != nil {
			return err
		}
		if jsonOut {
			return common.PrintJSON(map[string]any{"ok": true, "value": val})
		}
		fmt.Printf("%v\n", val)
		return nil

	case "html":
		fs := flag.NewFlagSet("cdp html", flag.ContinueOnError)
		tabID := fs.String("tab", "", "target tab ID")
		selector := fs.String("selector", "", "optional CSS selector")
		outPath := fs.String("out", "", "optional file path to save HTML")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		tab, err := cdp.ResolveTab(port, *tabID)
		if err != nil {
			return err
		}
		c, err := cdp.Connect(tab.WebSocketDebuggerURL)
		if err != nil {
			return err
		}
		defer c.Close()
		html, err := c.GetHTML(*selector)
		if err != nil {
			return err
		}
		if *outPath != "" {
			if err := common.WriteFileAtomic(*outPath, []byte(html), 0o600); err != nil {
				return err
			}
			abs, _ := filepath.Abs(*outPath)
			if jsonOut {
				return common.PrintJSON(map[string]any{"ok": true, "path": abs, "bytes": len(html)})
			}
			fmt.Printf("Saved HTML (%d bytes) -> %s\n", len(html), abs)
			return nil
		}
		if jsonOut {
			return common.PrintJSON(map[string]any{"ok": true, "html": html})
		}
		fmt.Println(html)
		return nil

	case "screenshot":
		fs := flag.NewFlagSet("cdp screenshot", flag.ContinueOnError)
		tabID := fs.String("tab", "", "target tab ID")
		outPath := fs.String("out", "screenshot.png", "output PNG path")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		tab, err := cdp.ResolveTab(port, *tabID)
		if err != nil {
			return err
		}
		c, err := cdp.Connect(tab.WebSocketDebuggerURL)
		if err != nil {
			return err
		}
		defer c.Close()
		png, err := c.Screenshot()
		if err != nil {
			return err
		}
		if err := common.WriteFileAtomic(*outPath, png, 0o600); err != nil {
			return err
		}
		abs, _ := filepath.Abs(*outPath)
		if jsonOut {
			return common.PrintJSON(map[string]any{"ok": true, "path": abs, "bytes": len(png)})
		}
		fmt.Printf("Saved screenshot (%d bytes) -> %s\n", len(png), abs)
		return nil

	case "pdf":
		fs := flag.NewFlagSet("cdp pdf", flag.ContinueOnError)
		tabID := fs.String("tab", "", "target tab ID")
		outPath := fs.String("out", "page.pdf", "output PDF path")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		tab, err := cdp.ResolveTab(port, *tabID)
		if err != nil {
			return err
		}
		c, err := cdp.Connect(tab.WebSocketDebuggerURL)
		if err != nil {
			return err
		}
		defer c.Close()
		pdfBytes, err := c.PrintPDF()
		if err != nil {
			return err
		}
		if err := common.WriteFileAtomic(*outPath, pdfBytes, 0o600); err != nil {
			return err
		}
		abs, _ := filepath.Abs(*outPath)
		if jsonOut {
			return common.PrintJSON(map[string]any{"ok": true, "path": abs, "bytes": len(pdfBytes)})
		}
		fmt.Printf("Saved PDF (%d bytes) -> %s\n", len(pdfBytes), abs)
		return nil

	case "cookies":
		fs := flag.NewFlagSet("cdp cookies", flag.ContinueOnError)
		tabID := fs.String("tab", "", "target tab ID")
		includeValues := fs.Bool("include-values", false, "include raw cookie values (redacted by default)")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		tab, err := cdp.ResolveTab(port, *tabID)
		if err != nil {
			return err
		}
		c, err := cdp.Connect(tab.WebSocketDebuggerURL)
		if err != nil {
			return err
		}
		defer c.Close()
		cookies, err := c.GetCookies(*includeValues)
		if err != nil {
			return err
		}
		if jsonOut {
			return common.PrintJSON(cookies)
		}
		if len(cookies) == 0 {
			fmt.Println("No cookies.")
			return nil
		}
		for _, ck := range cookies {
			fmt.Printf("%-24s  %-24s  %s\n", ck.Domain, ck.Name, ck.Value)
		}
		return nil

	case "export-cookies":
		fs := flag.NewFlagSet("cdp export-cookies", flag.ContinueOnError)
		tabID := fs.String("tab", "", "target tab ID")
		outPath := fs.String("out", "cookies.json", "output JSON file (0600 permissions)")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		tab, err := cdp.ResolveTab(port, *tabID)
		if err != nil {
			return err
		}
		c, err := cdp.Connect(tab.WebSocketDebuggerURL)
		if err != nil {
			return err
		}
		defer c.Close()
		cookies, err := c.GetCookies(true)
		if err != nil {
			return err
		}
		raw, err := json.MarshalIndent(cookies, "", "  ")
		if err != nil {
			return err
		}
		if err := common.WriteFileAtomic(*outPath, raw, 0o600); err != nil {
			return err
		}
		abs, _ := filepath.Abs(*outPath)
		if jsonOut {
			return common.PrintJSON(map[string]any{"ok": true, "count": len(cookies), "path": abs})
		}
		fmt.Printf("Exported %d cookie(s) -> %s\n", len(cookies), abs)
		return nil

	case "set-cookies":
		fs := flag.NewFlagSet("cdp set-cookies", flag.ContinueOnError)
		tabID := fs.String("tab", "", "target tab ID")
		filePath := fs.String("file", "", "JSON cookies file to import")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *filePath == "" {
			return errors.New("--file is required")
		}
		raw, err := os.ReadFile(*filePath)
		if err != nil {
			return err
		}
		var cookies []cdp.CookieItem
		if err := json.Unmarshal(raw, &cookies); err != nil {
			return fmt.Errorf("parse cookies JSON: %w", err)
		}
		tab, err := cdp.ResolveTab(port, *tabID)
		if err != nil {
			return err
		}
		c, err := cdp.Connect(tab.WebSocketDebuggerURL)
		if err != nil {
			return err
		}
		defer c.Close()
		n, err := c.SetCookies(cookies)
		if err != nil {
			return err
		}
		if jsonOut {
			return common.PrintJSON(map[string]any{"ok": true, "imported": n})
		}
		fmt.Printf("Imported %d cookie(s)\n", n)
		return nil

	case "console":
		fs := flag.NewFlagSet("cdp console", flag.ContinueOnError)
		tabID := fs.String("tab", "", "target tab ID")
		duration := fs.Duration("duration", 5*time.Second, "capture duration")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		tab, err := cdp.ResolveTab(port, *tabID)
		if err != nil {
			return err
		}
		c, err := cdp.Connect(tab.WebSocketDebuggerURL)
		if err != nil {
			return err
		}
		defer c.Close()
		entries, err := c.CaptureConsole(*duration)
		if err != nil {
			return err
		}
		if jsonOut {
			return common.PrintJSON(entries)
		}
		if len(entries) == 0 {
			fmt.Println("No console events captured.")
			return nil
		}
		for _, e := range entries {
			fmt.Printf("[%s] %s\n", strings.ToUpper(e.Kind), e.Text)
		}
		return nil

	case "network":
		fs := flag.NewFlagSet("cdp network", flag.ContinueOnError)
		tabID := fs.String("tab", "", "target tab ID")
		duration := fs.Duration("duration", 5*time.Second, "capture duration")
		filter := fs.String("filter", "", "URL substring filter")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		tab, err := cdp.ResolveTab(port, *tabID)
		if err != nil {
			return err
		}
		c, err := cdp.Connect(tab.WebSocketDebuggerURL)
		if err != nil {
			return err
		}
		defer c.Close()
		entries, err := c.CaptureNetwork(*duration, *filter)
		if err != nil {
			return err
		}
		if jsonOut {
			return common.PrintJSON(entries)
		}
		if len(entries) == 0 {
			fmt.Println("No network requests captured.")
			return nil
		}
		for _, e := range entries {
			stStr := fmt.Sprintf("%d", e.Status)
			if e.Failed {
				stStr = "ERR:" + e.ErrorText
			}
			fmt.Printf("%-6s %-8s %s\n", e.Method, stStr, e.URL)
		}
		return nil

	default:
		return fmt.Errorf("unknown cdp subcommand %q", action)
	}
}
