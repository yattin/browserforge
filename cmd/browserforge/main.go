package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"browserforge/internal/common"
	"browserforge/internal/daemon"
	"browserforge/internal/fingerprint"
	"browserforge/internal/kernel"
	"browserforge/internal/launcher"
	"browserforge/internal/proxyfwd"
	"browserforge/internal/selftest"
	"browserforge/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}
	// Hidden internal subprocess for per-profile proxy forwarder.
	if os.Args[1] == "_forwarder" {
		if err := proxyfwd.RunSubprocess(); err != nil {
			fmt.Fprintln(os.Stderr, "forwarder error:", err)
			os.Exit(1)
		}
		return
	}

	dataDir, jsonOut, args := extractGlobalFlags(os.Args[1:])
	if len(args) == 0 {
		printUsage()
		os.Exit(0)
	}

	cmd := args[0]
	sub := args[1:]
	var err error
	switch cmd {
	case "help", "-h", "--help":
		printUsage()
		return
	case "version":
		err = cmdVersion(jsonOut)
	case "doctor":
		err = cmdDoctor(dataDir, jsonOut)
	case "kernel":
		err = cmdKernel(dataDir, jsonOut, sub)
	case "profile":
		err = cmdProfile(dataDir, jsonOut, sub)
	case "proxy":
		err = cmdProxy(dataDir, jsonOut, sub)
	case "start":
		err = cmdStart(dataDir, jsonOut, sub)
	case "stop":
		err = cmdStop(dataDir, jsonOut, sub)
	case "ps":
		err = cmdPS(dataDir, jsonOut)
	case "cdp":
		err = cmdCDP(dataDir, jsonOut, sub)
	case "daemon":
		err = cmdDaemon(dataDir, jsonOut, sub)
	case "selftest":
		err = cmdSelfTest(dataDir, jsonOut, sub)
	default:
		err = fmt.Errorf("unknown command %q (run 'browserforge help')", cmd)
	}

	if err != nil {
		if jsonOut {
			_ = common.PrintJSON(map[string]any{"ok": false, "error": err.Error()})
		} else {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(1)
	}
}

func extractGlobalFlags(args []string) (dataDir string, jsonOut bool, rest []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json":
			jsonOut = true
		case a == "--data-dir" && i+1 < len(args):
			dataDir = args[i+1]
			i++
		case strings.HasPrefix(a, "--data-dir="):
			dataDir = strings.TrimPrefix(a, "--data-dir=")
		default:
			rest = append(rest, a)
		}
	}
	return dataDir, jsonOut, rest
}

func printUsage() {
	fmt.Println(`BrowserForge - Standalone Anti-Detect Browser CLI (Pure Go, Zero Dependencies)

Usage:
  browserforge <command> [subcommand] [flags]

Global Flags:
  --data-dir <dir>   Override data directory (default: %LOCALAPPDATA%\BrowserForge)
  --json             Emit structured JSON output

Commands:
  version                                     Show CLI version
  doctor                                      Inspect host hardware, store & kernels
  kernel list | set <exe-path>                List or set default browser kernel
  profile list|create|show|update|validate|reset-fp|clone|delete
  proxy list|add|import|check|remove          Manage encrypted upstream proxies
  start <id|name> [--headless] [--url <u...>] Launch isolated browser (auto-delegates to foreground daemon)
  stop <id|name | --all>                      Stop running browser & proxy forwarder
  ps                                          List running browser instances
  daemon start | status | stop                Run or manage lightweight foreground GUI launcher daemon
  cdp tabs|open|navigate|close-tab|wait|snapshot|click|type|scroll|hover|press|eval|html|screenshot|pdf|cookies|export-cookies|set-cookies|console|network
  selftest [--with-browser]                   Run built-in security & integration suite`)
}

func cmdVersion(jsonOut bool) error {
	if jsonOut {
		return common.PrintJSON(map[string]any{"version": common.AppVersion})
	}
	fmt.Printf("browserforge %s\n", common.AppVersion)
	return nil
}

// parseFlagsFlexible reorders flags before positional arguments using fs.Lookup so flags work anywhere on the command line.
func parseFlagsFlexible(fs *flag.FlagSet, args []string) error {
	var flags, pos []string
	type boolFlag interface {
		IsBoolFlag() bool
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			flags = append(flags, a)
			if strings.Contains(a, "=") {
				continue
			}
			name := strings.TrimLeft(a, "-")
			f := fs.Lookup(name)
			isBool := false
			if f != nil {
				if bf, ok := f.Value.(boolFlag); ok && bf.IsBoolFlag() {
					isBool = true
				}
			}
			if !isBool && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		} else {
			pos = append(pos, a)
		}
	}
	return fs.Parse(append(flags, pos...))
}

func cmdDoctor(dataDir string, jsonOut bool) error {
	st, err := store.Open(dataDir)
	if err != nil {
		return err
	}
	cfg, err := st.LoadSettings()
	if err != nil {
		return err
	}
	host := fingerprint.DetectHost()
	kernels := kernel.Discover(cfg.KernelExe)
	profiles, _ := st.ListProfiles()
	proxies, _ := st.ListProxies()
	dmState, dmErr := daemon.Probe(st.DataDir)
	daemonInfo := map[string]any{"running": false}
	if dmErr == nil && dmState != nil {
		daemonInfo = map[string]any{
			"running": true,
			"pid":     dmState.PID,
			"port":    dmState.Port,
			"version": dmState.Version,
		}
	}

	out := map[string]any{
		"ok":               len(kernels) > 0,
		"version":          common.AppVersion,
		"data_dir":         st.DataDir,
		"host":             host,
		"default_template": fingerprint.DefaultTemplateID(host.OS, host.GPUVendor),
		"kernels":          kernels,
		"daemon":           daemonInfo,
		"profile_count":    len(profiles),
		"proxy_count":      len(proxies),
	}
	if jsonOut {
		return common.PrintJSON(out)
	}
	fmt.Printf("BrowserForge %s\n", common.AppVersion)
	fmt.Printf("Data Dir : %s\n", st.DataDir)
	fmt.Printf("Host     : %s | %d cores | %d GB RAM | %dx%d | GPU=%s\n",
		host.OS, host.Cores, host.MemoryGB, host.ScreenWidth, host.ScreenHeight, host.GPUVendor)
	if dmErr == nil && dmState != nil {
		fmt.Printf("Daemon   : running (pid=%d port=127.0.0.1:%d v%s)\n", dmState.PID, dmState.Port, dmState.Version)
	} else {
		fmt.Printf("Daemon   : stopped\n")
	}
	fmt.Printf("Profiles : %d | Proxies: %d\n", len(profiles), len(proxies))
	fmt.Printf("Kernels  : %d discovered\n", len(kernels))
	for i, k := range kernels {
		mark := " "
		if i == 0 {
			mark = "*"
		}
		fmt.Printf("  %s [%s] v%s  %s\n", mark, k.Kind, k.Version, k.ExePath)
	}
	return nil
}

func cmdKernel(dataDir string, jsonOut bool, args []string) error {
	st, err := store.Open(dataDir)
	if err != nil {
		return err
	}
	cfg, err := st.LoadSettings()
	if err != nil {
		return err
	}
	if len(args) == 0 || args[0] == "list" {
		list := kernel.Discover(cfg.KernelExe)
		if jsonOut {
			return common.PrintJSON(map[string]any{"configured": cfg.KernelExe, "kernels": list})
		}
		if len(list) == 0 {
			fmt.Println("No browser kernels found. Use 'browserforge kernel set <path>' or BROWSERFORGE_KERNEL_EXE.")
			return nil
		}
		for i, k := range list {
			mark := " "
			if i == 0 {
				mark = "*"
			}
			fmt.Printf("%s [%s] %-14s %s\n", mark, k.Kind, k.Version, k.ExePath)
		}
		return nil
	}
	if args[0] == "set" {
		if len(args) < 2 {
			return errors.New("usage: browserforge kernel set <path-to-chrome.exe>")
		}
		abs, err := filepath.Abs(args[1])
		if err != nil {
			return err
		}
		info, err := os.Stat(abs)
		if err != nil || info.IsDir() {
			return fmt.Errorf("kernel executable not found: %s", abs)
		}
		cfg.KernelExe = abs
		if err := st.SaveSettings(cfg); err != nil {
			return err
		}
		ver := kernel.ReadExecutableVersion(abs)
		if jsonOut {
			return common.PrintJSON(map[string]any{"ok": true, "kernel_exe": abs, "version": ver})
		}
		fmt.Printf("Default kernel set to %s (v%s)\n", abs, ver)
		return nil
	}
	return fmt.Errorf("unknown kernel subcommand %q", args[0])
}

func cmdProxy(dataDir string, jsonOut bool, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: browserforge proxy <list|add|check|remove>")
	}
	st, err := store.Open(dataDir)
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		list, err := st.ListProxies()
		if err != nil {
			return err
		}
		pub := make([]store.PublicProxy, len(list))
		for i, p := range list {
			pub[i] = p.Public()
		}
		if jsonOut {
			return common.PrintJSON(pub)
		}
		if len(pub) == 0 {
			fmt.Println("No proxies configured.")
			return nil
		}
		for _, p := range pub {
			auth := "no-auth"
			if p.Username != "" || p.HasPassword {
				auth = "auth:" + p.Username
			}
			fmt.Printf("%-36s  %-16s  %s://%s:%d  (%s)  exit=%s %s\n",
				p.ID, p.Name, p.Scheme, p.Host, p.Port, auth, p.ExitIP, p.ExitTimezone)
		}
		return nil

	case "add":
		fs := flag.NewFlagSet("proxy add", flag.ContinueOnError)
		name := fs.String("name", "", "proxy name")
		rawURL := fs.String("url", "", "proxy URL e.g. http://host:port or socks5://user@host:port")
		user := fs.String("user", "", "proxy username")
		passEnv := fs.String("pass-env", "", "environment variable containing proxy password")
		pass := fs.String("pass", "", "proxy password (prefer --pass-env)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *rawURL == "" {
			return errors.New("--url is required (e.g. --url http://proxy.example.com:8080)")
		}
		u, err := url.Parse(*rawURL)
		if err != nil {
			return fmt.Errorf("invalid proxy URL: %w", err)
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" && scheme != "socks5" {
			return fmt.Errorf("unsupported proxy scheme %q (supported: http, https, socks5)", scheme)
		}
		host := u.Hostname()
		portStr := u.Port()
		if host == "" || portStr == "" {
			return errors.New("proxy URL must include host and port")
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid proxy port %q", portStr)
		}
		username := *user
		password := *pass
		if u.User != nil {
			if username == "" {
				username = u.User.Username()
			}
			if p, ok := u.User.Password(); ok && password == "" {
				password = p
			}
		}
		if *passEnv != "" {
			password = os.Getenv(*passEnv)
		}
		encPass, err := common.ProtectSecret(st.DataDir, password)
		if err != nil {
			return fmt.Errorf("encrypt proxy password: %w", err)
		}
		id, err := common.NewUUIDv4()
		if err != nil {
			return err
		}
		pName := strings.TrimSpace(*name)
		if pName == "" {
			pName = fmt.Sprintf("%s-%s-%d", scheme, host, port)
		}
		if _, err := st.FindProxy(pName); err == nil {
			return fmt.Errorf("proxy name %q already exists", pName)
		}
		rec := store.ProxyRecord{
			ID:          id,
			Name:        pName,
			Scheme:      scheme,
			Host:        host,
			Port:        port,
			Username:    username,
			PasswordEnc: encPass,
			CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		}
		list, err := st.ListProxies()
		if err != nil {
			return err
		}
		list = append(list, rec)
		if err := st.SaveProxies(list); err != nil {
			return err
		}
		if jsonOut {
			return common.PrintJSON(rec.Public())
		}
		fmt.Printf("Added proxy %s (%s) -> %s://%s:%d\n", rec.Name, rec.ID, rec.Scheme, rec.Host, rec.Port)
		return nil

	case "check":
		fs := flag.NewFlagSet("proxy check", flag.ContinueOnError)
		probeURL := fs.String("probe-url", "", "override probe endpoint URL")
		allowLocal := fs.Bool("allow-local", false, "allow loopback/LAN targets for local testing")
		allowLocalUp := fs.Bool("allow-local-upstream", false, "allow loopback/LAN upstream proxy server")
		if err := parseFlagsFlexible(fs, args[1:]); err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return errors.New("usage: browserforge proxy check <id|name>")
		}
		rec, err := st.FindProxy(fs.Arg(0))
		if err != nil {
			return err
		}
		pass, err := common.UnprotectSecret(st.DataDir, rec.PasswordEnc)
		if err != nil {
			return err
		}
		res := proxyfwd.ProbeUpstream(context.Background(), proxyfwd.UpstreamConfig{
			Scheme:             rec.Scheme,
			Host:               rec.Host,
			Port:               rec.Port,
			Username:           rec.Username,
			Password:           pass,
			AllowLocal:         *allowLocal,
			AllowLocalUpstream: *allowLocalUp,
		}, *probeURL)

		if res.OK {
			list, _ := st.ListProxies()
			for i := range list {
				if list[i].ID == rec.ID {
					list[i].ExitIP = res.ExitIP
					list[i].ExitCountry = res.Country
					list[i].ExitTimezone = res.Timezone
					list[i].LastCheckedAt = time.Now().UTC().Format(time.RFC3339)
				}
			}
			_ = st.SaveProxies(list)
		}
		if jsonOut {
			return common.PrintJSON(res)
		}
		if !res.OK {
			return fmt.Errorf("proxy check failed (%dms): %s", res.LatencyMS, res.Error)
		}
		fmt.Printf("Proxy %s OK (%dms) exit_ip=%s country=%s timezone=%s\n",
			rec.Name, res.LatencyMS, res.ExitIP, res.Country, res.Timezone)
		return nil

	case "import":
		return cmdProxyImport(st, jsonOut, args[1:])

	case "remove":
		fs := flag.NewFlagSet("proxy remove", flag.ContinueOnError)
		force := fs.Bool("force", false, "force removal and unbind from referencing profiles")
		if err := parseFlagsFlexible(fs, args[1:]); err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return errors.New("usage: browserforge proxy remove [--force] <id|name>")
		}
		rec, err := st.FindProxy(fs.Arg(0))
		if err != nil {
			return err
		}
		profiles, _ := st.ListProfiles()
		var bound []string
		for _, p := range profiles {
			if p.ProxyID == rec.ID {
				bound = append(bound, p.Name)
			}
		}
		if len(bound) > 0 && !*force {
			return fmt.Errorf("proxy %q is bound to profile(s): %s (pass --force to unbind and remove)", rec.Name, strings.Join(bound, ", "))
		}
		if len(bound) > 0 && *force {
			for i := range profiles {
				if profiles[i].ProxyID == rec.ID {
					profiles[i].ProxyID = ""
				}
			}
			if err := st.SaveProfiles(profiles); err != nil {
				return err
			}
		}
		list, err := st.ListProxies()
		if err != nil {
			return err
		}
		out := make([]store.ProxyRecord, 0, len(list))
		for _, p := range list {
			if p.ID != rec.ID {
				out = append(out, p)
			}
		}
		if err := st.SaveProxies(out); err != nil {
			return err
		}
		if jsonOut {
			return common.PrintJSON(map[string]any{"ok": true, "removed": rec.ID, "unbound_profiles": bound})
		}
		fmt.Printf("Removed proxy %s (%s)\n", rec.Name, rec.ID)
		return nil
	default:
		return fmt.Errorf("unknown proxy subcommand %q", args[0])
	}
}

func cmdProfile(dataDir string, jsonOut bool, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: browserforge profile <list|create|show|update|validate|reset-fp|delete>")
	}
	st, err := store.Open(dataDir)
	if err != nil {
		return err
	}
	cfg, _ := st.LoadSettings()

	switch args[0] {
	case "list":
		list, err := st.ListProfiles()
		if err != nil {
			return err
		}
		if jsonOut {
			return common.PrintJSON(list)
		}
		if len(list) == 0 {
			fmt.Println("No profiles found. Create one with 'browserforge profile create --name <name>'.")
			return nil
		}
		for _, p := range list {
			status := "stopped"
			if rt, _ := st.LoadRuntime(p.ID); rt != nil && kernel.IsProcessAlive(rt.BrowserPID) {
				status = fmt.Sprintf("running(pid=%d,cdp=%d)", rt.BrowserPID, rt.DebugPort)
			}
			fmt.Printf("%-36s  %-18s  %-16s  %-18s  %s\n", p.ID, p.Name, p.Template, p.Timezone, status)
		}
		return nil

	case "create":
		fs := flag.NewFlagSet("profile create", flag.ContinueOnError)
		name := fs.String("name", "", "profile display name")
		group := fs.String("group", "", "optional group tag")
		tmpl := fs.String("template", "", "fingerprint template (default: auto-match host)")
		tz := fs.String("timezone", "", "IANA timezone (default: America/New_York)")
		langs := fs.String("lang", "", "comma-separated languages (default: en-US,en)")
		proxyRef := fs.String("proxy", "", "optional proxy ID or name")
		syncProxy := fs.Bool("sync-proxy", false, "auto-align timezone & locale with bound proxy exit IP")
		if err := parseFlagsFlexible(fs, args[1:]); err != nil {
			return err
		}
		profName := strings.TrimSpace(*name)
		if profName == "" {
			return errors.New("--name is required")
		}
		if _, err := st.FindProfile(profName); err == nil {
			return fmt.Errorf("profile name %q already exists", profName)
		}
		host := fingerprint.DetectHost()
		k := kernel.Resolve(cfg.KernelExe)
		browserVer := "156.0.8078.79"
		brand := "Google Chrome"
		if k != nil {
			if k.Version != "" {
				browserVer = k.Version
			}
			brand = k.Brand
		}
		tID := *tmpl
		if tID == "" {
			tID = fingerprint.DefaultTemplateID(host.OS, host.GPUVendor)
		}
		proxyID := ""
		var boundProxy *store.ProxyRecord
		if *proxyRef != "" {
			pr, err := st.FindProxy(*proxyRef)
			if err != nil {
				return err
			}
			proxyID = pr.ID
			boundProxy = pr
			if *syncProxy && pr.ExitTimezone == "" {
				pass, decErr := common.UnprotectSecret(st.DataDir, pr.PasswordEnc)
				if decErr == nil {
					res := proxyfwd.ProbeUpstream(context.Background(), proxyfwd.UpstreamConfig{
						Scheme:   pr.Scheme,
						Host:     pr.Host,
						Port:     pr.Port,
						Username: pr.Username,
						Password: pass,
					}, "")
					if res.OK {
						pr.ExitIP = res.ExitIP
						pr.ExitCountry = res.Country
						pr.ExitTimezone = res.Timezone
						pr.LastCheckedAt = time.Now().UTC().Format(time.RFC3339)
						plist, _ := st.ListProxies()
						for i := range plist {
							if plist[i].ID == pr.ID {
								plist[i] = *pr
							}
						}
						_ = st.SaveProxies(plist)
					}
				}
			}
		}
		timezone := *tz
		if timezone == "" && *syncProxy && boundProxy != nil && boundProxy.ExitTimezone != "" {
			timezone = boundProxy.ExitTimezone
		}
		if timezone == "" {
			timezone = cfg.Timezone
			if timezone == "" {
				timezone = "America/New_York"
			}
		}
		langList := splitCSV(*langs)
		if len(langList) == 0 && *syncProxy && boundProxy != nil && boundProxy.ExitCountry != "" {
			langList = defaultLangsForCountry(boundProxy.ExitCountry)
		}
		if len(langList) == 0 {
			langList = cfg.Languages
			if len(langList) == 0 {
				langList = []string{"en-US", "en"}
			}
		}

		id, err := common.NewUUIDv4()
		if err != nil {
			return err
		}
		fp, err := fingerprint.Generate(fingerprint.GenerateParams{
			ProfileID:      id,
			Template:       tID,
			BrowserVersion: browserVer,
			Brand:          brand,
			Timezone:       timezone,
			Languages:      langList,
			Host:           host,
		})
		if err != nil {
			return err
		}
		now := time.Now().UTC().Format(time.RFC3339)
		rec := store.ProfileRecord{
			ID:        id,
			Name:      strings.TrimSpace(*name),
			Group:     strings.TrimSpace(*group),
			Template:  tID,
			ProxyID:   proxyID,
			Timezone:  timezone,
			Languages: langList,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := st.InitProfileLayout(rec, fp); err != nil {
			return err
		}
		list, err := st.ListProfiles()
		if err != nil {
			return err
		}
		list = append(list, rec)
		if err := st.SaveProfiles(list); err != nil {
			return err
		}
		if jsonOut {
			return common.PrintJSON(map[string]any{"profile": rec, "fingerprint_checksum": fp.Checksum, "algorithm": fp.Algorithm})
		}
		fmt.Printf("Created profile %s (%s)\n  template=%s tz=%s lang=%s fp=%s(%s...)\n",
			rec.Name, rec.ID, rec.Template, rec.Timezone, strings.Join(rec.Languages, ","), fp.Algorithm, fp.Checksum[:12])
		return nil

	case "show":
		if len(args) < 2 {
			return errors.New("usage: browserforge profile show <id|name>")
		}
		rec, err := st.FindProfile(args[1])
		if err != nil {
			return err
		}
		fp, isRO, fpErr := st.LoadFingerprint(rec.ID)
		rt, _ := st.LoadRuntime(rec.ID)
		running := rt != nil && kernel.IsProcessAlive(rt.BrowserPID)
		out := map[string]any{
			"profile":        rec,
			"running":        running,
			"runtime":        rt,
			"fp_readonly":    isRO,
			"fp_path":        st.FingerprintPath(rec.ID),
			"userdata_dir":   st.UserDataDir(rec.ID),
		}
		if fpErr == nil && fp != nil {
			out["fingerprint"] = fp
		} else if fpErr != nil {
			out["fp_error"] = fpErr.Error()
		}
		if jsonOut {
			return common.PrintJSON(out)
		}
		fmt.Printf("Profile : %s (%s)\nTemplate: %s | TZ: %s | Lang: %s\nProxyID : %s | Running: %v\nFP Path : %s (readonly=%v)\n",
			rec.Name, rec.ID, rec.Template, rec.Timezone, strings.Join(rec.Languages, ","), rec.ProxyID, running, st.FingerprintPath(rec.ID), isRO)
		if fp != nil {
			fmt.Printf("FP      : %s | UA=%s | Screen=%dx%d | GPU=%s\n",
				fp.Algorithm, fp.Navigator.UA, fp.Screen.Width, fp.Screen.Height, fp.WebGL.Renderer)
		}
		return nil

	case "update":
		fs := flag.NewFlagSet("profile update", flag.ContinueOnError)
		tz := fs.String("timezone", "", "new IANA timezone")
		langs := fs.String("lang", "", "new comma-separated languages")
		proxyRef := fs.String("proxy", "", "new proxy ID/name (use 'none' to unbind)")
		if err := parseFlagsFlexible(fs, args[1:]); err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return errors.New("usage: browserforge profile update [--timezone ...] [--lang ...] [--proxy ...] <id|name>")
		}
		rec, err := st.FindProfile(fs.Arg(0))
		if err != nil {
			return err
		}
		fp, _, err := st.LoadFingerprint(rec.ID)
		if err != nil {
			return err
		}
		newLangs := splitCSV(*langs)
		if *tz != "" {
			rec.Timezone = *tz
		}
		if len(newLangs) > 0 {
			rec.Languages = newLangs
		}
		if *proxyRef == "none" {
			rec.ProxyID = ""
		} else if *proxyRef != "" {
			pr, err := st.FindProxy(*proxyRef)
			if err != nil {
				return err
			}
			rec.ProxyID = pr.ID
		}
		updatedFP, err := fp.WithEditable(rec.Timezone, rec.Languages, rec.Geolocation)
		if err != nil {
			return err
		}
		if err := st.WriteFingerprint(rec.ID, updatedFP); err != nil {
			return err
		}
		rec.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		list, _ := st.ListProfiles()
		for i := range list {
			if list[i].ID == rec.ID {
				list[i] = *rec
			}
		}
		if err := st.SaveProfiles(list); err != nil {
			return err
		}
		if jsonOut {
			return common.PrintJSON(map[string]any{"ok": true, "profile": rec, "checksum": updatedFP.Checksum})
		}
		fmt.Printf("Updated profile %s (checksum=%s...)\n", rec.Name, updatedFP.Checksum[:12])
		return nil

	case "validate":
		if len(args) < 2 {
			return errors.New("usage: browserforge profile validate <id|name>")
		}
		rec, err := st.FindProfile(args[1])
		if err != nil {
			return err
		}
		fp, isRO, err := st.LoadFingerprint(rec.ID)
		if err != nil {
			return err
		}
		k := kernel.Resolve(cfg.KernelExe)
		kVer := ""
		if k != nil {
			kVer = k.Version
		}
		vctx := fingerprint.ValidationContext{
			Host:          fingerprint.DetectHost(),
			KernelVersion: kVer,
			HasProxy:      rec.ProxyID != "",
			FileReadOnly:  isRO,
			ExpectedID:    rec.ID,
		}
		if rec.ProxyID != "" {
			if pr, err := st.FindProxy(rec.ProxyID); err == nil {
				vctx.ProxyCountry = pr.ExitCountry
				vctx.ProxyTimezone = pr.ExitTimezone
			}
		}
		rep := fingerprint.ValidateConsistency(fp, vctx)
		if jsonOut {
			return common.PrintJSON(rep)
		}
		fmt.Printf("Validation for %s: %s (ok=%v)\n", rec.Name, rep.Summary, rep.OK)
		for _, it := range rep.Items {
			fmt.Printf("  [%-4s] %-20s %s\n", strings.ToUpper(string(it.Status)), it.Code, it.Message)
		}
		if !rep.OK {
			return errors.New("profile failed consistency validation")
		}
		return nil

	case "reset-fp":
		if len(args) < 2 {
			return errors.New("usage: browserforge profile reset-fp <id|name>")
		}
		rec, err := st.FindProfile(args[1])
		if err != nil {
			return err
		}
		host := fingerprint.DetectHost()
		k := kernel.Resolve(cfg.KernelExe)
		ver, brand := "156.0.8078.79", "Google Chrome"
		if k != nil {
			if k.Version != "" {
				ver = k.Version
			}
			brand = k.Brand
		}
		fp, err := fingerprint.Generate(fingerprint.GenerateParams{
			ProfileID:      rec.ID,
			Template:       rec.Template,
			BrowserVersion: ver,
			Brand:          brand,
			Timezone:       rec.Timezone,
			Languages:      rec.Languages,
			Geolocation:    rec.Geolocation,
			Host:           host,
		})
		if err != nil {
			return err
		}
		if err := st.WriteFingerprint(rec.ID, fp); err != nil {
			return err
		}
		if jsonOut {
			return common.PrintJSON(map[string]any{"ok": true, "profile_id": rec.ID, "seed_prefix": fp.Seed[:8], "checksum": fp.Checksum})
		}
		fmt.Printf("Regenerated fingerprint for %s (seed=%s... checksum=%s...)\n", rec.Name, fp.Seed[:8], fp.Checksum[:12])
		return nil

	case "clone":
		return cmdProfileClone(st, cfg, jsonOut, args[1:])

	case "delete":
		if len(args) < 2 {
			return errors.New("usage: browserforge profile delete <id|name>")
		}
		rec, err := st.FindProfile(args[1])
		if err != nil {
			return err
		}
		_ = stopProfile(st, rec.ID)
		if err := st.DeleteProfileDir(rec.ID); err != nil {
			return err
		}
		list, _ := st.ListProfiles()
		out := make([]store.ProfileRecord, 0, len(list))
		for _, p := range list {
			if p.ID != rec.ID {
				out = append(out, p)
			}
		}
		if err := st.SaveProfiles(out); err != nil {
			return err
		}
		if jsonOut {
			return common.PrintJSON(map[string]any{"ok": true, "deleted": rec.ID})
		}
		fmt.Printf("Deleted profile %s (%s)\n", rec.Name, rec.ID)
		return nil

	default:
		return fmt.Errorf("unknown profile subcommand %q", args[0])
	}
}

func cmdStart(dataDir string, jsonOut bool, args []string) error {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	headless := fs.Bool("headless", false, "launch in headless=new mode")
	startURL := fs.String("url", "", "initial URL to open")
	allowLocal := fs.Bool("allow-local", false, "allow proxy destinations to loopback/LAN (testing only)")
	allowLocalUp := fs.Bool("allow-local-upstream", false, "allow upstream proxy server on loopback/LAN")
	kernelOverride := fs.String("kernel", "", "override browser kernel executable path")
	direct := fs.Bool("direct", false, "bypass foreground daemon and launch directly in current session")
	if err := parseFlagsFlexible(fs, args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return errors.New("usage: browserforge start [--headless] [--url ...] [--direct] <profile-id|name>")
	}
	st, err := store.Open(dataDir)
	if err != nil {
		return err
	}

	req := launcher.StartRequest{
		ProfileRef:         fs.Arg(0),
		Headless:           *headless,
		StartURL:           *startURL,
		AllowLocal:         *allowLocal,
		AllowLocalUpstream: *allowLocalUp,
		KernelOverride:     *kernelOverride,
	}

	var res *launcher.StartResult
	if !*direct {
		if dst, err := daemon.Probe(st.DataDir); err == nil && dst != nil {
			res, err = daemon.RemoteStart(dst, req)
			if err != nil {
				return err
			}
		}
	}
	if res == nil {
		res, err = launcher.StartProfile(st, req)
		if err != nil {
			return err
		}
	}

	if jsonOut {
		return common.PrintJSON(res)
	}
	if res.AlreadyRunning {
		fmt.Printf("Profile %s already running (pid=%d cdp=127.0.0.1:%d)\n",
			res.Profile, res.Runtime.BrowserPID, res.Runtime.DebugPort)
		return nil
	}
	via := ""
	if res.ViaDaemon {
		via = " [via foreground daemon]"
	}
	fmt.Printf("Started %s (%s)%s\n  browser_pid=%d cdp=127.0.0.1:%d proxy_port=%d kernel=%s(%s)\n",
		res.Profile, res.Runtime.ProfileID, via,
		res.Runtime.BrowserPID, res.Runtime.DebugPort, res.Runtime.ProxyPort, res.KernelKind, res.KernelVersion)
	return nil
}

func stopProfile(st *store.Store, profileID string) error {
	return launcher.StopProfile(st, profileID)
}

func cmdDaemon(dataDir string, jsonOut bool, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: browserforge daemon <start|status|stop>")
	}
	st, err := store.Open(dataDir)
	if err != nil {
		return err
	}
	switch args[0] {
	case "start":
		srv, err := daemon.NewServer(st)
		if err != nil {
			return err
		}
		ds := srv.State()
		if jsonOut {
			_ = common.PrintJSON(map[string]any{"ok": true, "pid": ds.PID, "port": ds.Port, "state_file": daemon.StatePath(st.DataDir)})
		} else {
			fmt.Printf("BrowserForge foreground daemon listening on 127.0.0.1:%d (pid=%d)\n", ds.Port, ds.PID)
			fmt.Printf("State file: %s (Press Ctrl+C to stop)\n", daemon.StatePath(st.DataDir))
		}
		return srv.Serve()

	case "status":
		ds, err := daemon.Probe(st.DataDir)
		if err != nil {
			if jsonOut {
				return common.PrintJSON(map[string]any{"running": false})
			}
			fmt.Println("Foreground daemon is not running.")
			return nil
		}
		if jsonOut {
			return common.PrintJSON(map[string]any{
				"running":    true,
				"pid":        ds.PID,
				"port":       ds.Port,
				"version":    ds.Version,
				"started_at": ds.StartedAt,
			})
		}
		fmt.Printf("Foreground daemon running: pid=%d port=127.0.0.1:%d version=%s started=%s\n",
			ds.PID, ds.Port, ds.Version, ds.StartedAt)
		return nil

	case "stop":
		ds, err := daemon.Probe(st.DataDir)
		if err != nil {
			if jsonOut {
				return common.PrintJSON(map[string]any{"ok": true, "running": false})
			}
			fmt.Println("Foreground daemon is not running.")
			return nil
		}
		if err := daemon.RemoteShutdown(ds); err != nil {
			return err
		}
		if jsonOut {
			return common.PrintJSON(map[string]any{"ok": true, "stopped_pid": ds.PID})
		}
		fmt.Printf("Stopped foreground daemon (pid=%d)\n", ds.PID)
		return nil

	default:
		return fmt.Errorf("unknown daemon subcommand %q (expected start|status|stop)", args[0])
	}
}

func cmdStop(dataDir string, jsonOut bool, args []string) error {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	stopAll := fs.Bool("all", false, "stop all running profiles")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := store.Open(dataDir)
	if err != nil {
		return err
	}
	var stopped []string
	if *stopAll {
		list, err := st.ListProfiles()
		if err != nil {
			return err
		}
		for _, p := range list {
			if rt, _ := st.LoadRuntime(p.ID); rt != nil {
				_ = stopProfile(st, p.ID)
				stopped = append(stopped, p.ID)
			}
		}
	} else {
		if fs.NArg() < 1 {
			return errors.New("usage: browserforge stop <id|name> | --all")
		}
		rec, err := st.FindProfile(fs.Arg(0))
		if err != nil {
			return err
		}
		if err := stopProfile(st, rec.ID); err != nil {
			return err
		}
		stopped = append(stopped, rec.ID)
	}
	if jsonOut {
		return common.PrintJSON(map[string]any{"ok": true, "stopped": stopped})
	}
	fmt.Printf("Stopped %d profile(s)\n", len(stopped))
	return nil
}

func cmdPS(dataDir string, jsonOut bool) error {
	st, err := store.Open(dataDir)
	if err != nil {
		return err
	}
	list, err := st.ListProfiles()
	if err != nil {
		return err
	}
	type psItem struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		BrowserPID int    `json:"browser_pid"`
		ProxyPID   int    `json:"proxy_pid,omitempty"`
		ProxyPort  int    `json:"proxy_port,omitempty"`
		DebugPort  int    `json:"debug_port"`
		StartedAt  string `json:"started_at"`
	}
	var active []psItem
	for _, p := range list {
		rt, err := st.LoadRuntime(p.ID)
		if err != nil || rt == nil {
			continue
		}
		if !kernel.IsProcessAlive(rt.BrowserPID) {
			_ = st.ClearRuntime(p.ID)
			continue
		}
		active = append(active, psItem{
			ID:         p.ID,
			Name:       p.Name,
			BrowserPID: rt.BrowserPID,
			ProxyPID:   rt.ProxyPID,
			ProxyPort:  rt.ProxyPort,
			DebugPort:  rt.DebugPort,
			StartedAt:  rt.StartedAt,
		})
	}
	if jsonOut {
		return common.PrintJSON(active)
	}
	if len(active) == 0 {
		fmt.Println("No running browser instances.")
		return nil
	}
	for _, a := range active {
		fmt.Printf("%-36s  %-16s  pid=%-6d  cdp=127.0.0.1:%-5d  proxy=%d\n",
			a.ID, a.Name, a.BrowserPID, a.DebugPort, a.ProxyPort)
	}
	return nil
}

func resolveRunningRuntime(st *store.Store, profileRef string) (*store.RuntimeState, error) {
	rec, err := st.FindProfile(profileRef)
	if err != nil {
		return nil, err
	}
	rt, err := st.LoadRuntime(rec.ID)
	if err != nil || rt == nil || !kernel.IsProcessAlive(rt.BrowserPID) {
		return nil, fmt.Errorf("profile %s is not running (run 'browserforge start %s')", rec.Name, rec.Name)
	}
	return rt, nil
}

func cmdSelfTest(dataDir string, jsonOut bool, args []string) error {
	fs := flag.NewFlagSet("selftest", flag.ContinueOnError)
	withBrowser := fs.Bool("with-browser", false, "also launch a real browser kernel for CDP round-trip")
	if err := fs.Parse(args); err != nil {
		return err
	}
	configuredKernel := ""
	if st, err := store.Open(dataDir); err == nil {
		if cfg, err := st.LoadSettings(); err == nil {
			configuredKernel = cfg.KernelExe
		}
	}
	rep := selftest.Run(*withBrowser, configuredKernel)
	if jsonOut {
		_ = common.PrintJSON(rep)
	} else {
		for _, s := range rep.Stages {
			mark := "PASS"
			if !s.OK {
				mark = "FAIL"
			}
			fmt.Printf("[%s] %-46s (%s)  %s\n", mark, s.Name, s.Elapsed, s.Detail)
		}
	}
	if !rep.OK {
		return errors.New("selftest failed")
	}
	return nil
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-1]) + "…"
}
