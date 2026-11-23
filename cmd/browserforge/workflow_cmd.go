package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"browserforge/internal/common"
	"browserforge/internal/fingerprint"
	"browserforge/internal/kernel"
	"browserforge/internal/proxyfwd"
	"browserforge/internal/store"
)

var countryLangDefaults = map[string][]string{
	"US": {"en-US", "en"},
	"GB": {"en-GB", "en"},
	"AU": {"en-AU", "en"},
	"CA": {"en-CA", "en"},
	"SG": {"en-SG", "en-US", "en"},
	"PH": {"en-PH", "en-US", "en"},
	"VN": {"vi-VN", "vi", "en-US", "en"},
	"JP": {"ja-JP", "ja", "en-US", "en"},
	"KR": {"ko-KR", "ko", "en-US", "en"},
	"DE": {"de-DE", "de", "en-US", "en"},
	"FR": {"fr-FR", "fr", "en-US", "en"},
	"TW": {"zh-TW", "zh", "en-US", "en"},
	"HK": {"zh-HK", "zh", "en-US", "en"},
}

func defaultLangsForCountry(countryCode string) []string {
	if l, ok := countryLangDefaults[strings.ToUpper(strings.TrimSpace(countryCode))]; ok {
		return append([]string(nil), l...)
	}
	return []string{"en-US", "en"}
}

func cmdProxyImport(st *store.Store, jsonOut bool, args []string) error {
	fs := flag.NewFlagSet("proxy import", flag.ContinueOnError)
	prefix := fs.String("prefix", "proxy", "name prefix for imported proxies")
	doCheck := fs.Bool("check", false, "concurrently probe imported proxies for exit IP and timezone")
	probeURL := fs.String("probe-url", "", "override probe URL when --check is set")
	if err := parseFlagsFlexible(fs, args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return errors.New("usage: browserforge proxy import [--prefix s5] [--check] <file>")
	}

	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer f.Close()

	list, err := st.ListProxies()
	if err != nil {
		return err
	}
	existingNames := map[string]bool{}
	for _, p := range list {
		existingNames[strings.ToLower(p.Name)] = true
	}

	type importedItem struct {
		rec   store.ProxyRecord
		plain string
	}
	var added []importedItem
	sc := bufio.NewScanner(f)
	lineNo := 0
	nameIdx := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, err := url.Parse(line)
		if err != nil {
			return fmt.Errorf("line %d: invalid proxy URL (redacted)", lineNo)
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" && scheme != "socks5" {
			return fmt.Errorf("line %d: unsupported scheme %q", lineNo, scheme)
		}
		host, portStr := u.Hostname(), u.Port()
		port, err := strconv.Atoi(portStr)
		if host == "" || err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("line %d: invalid host/port", lineNo)
		}
		var user, pass string
		if u.User != nil {
			user = u.User.Username()
			pass, _ = u.User.Password()
		}
		encPass, err := common.ProtectSecret(st.DataDir, pass)
		if err != nil {
			return fmt.Errorf("line %d: encrypt proxy password: %w", lineNo, err)
		}
		id, err := common.NewUUIDv4()
		if err != nil {
			return err
		}
		var candidate string
		for {
			nameIdx++
			candidate = fmt.Sprintf("%s-%d", *prefix, nameIdx)
			if !existingNames[strings.ToLower(candidate)] {
				existingNames[strings.ToLower(candidate)] = true
				break
			}
		}
		rec := store.ProxyRecord{
			ID:          id,
			Name:        candidate,
			Scheme:      scheme,
			Host:        host,
			Port:        port,
			Username:    user,
			PasswordEnc: encPass,
			CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		}
		added = append(added, importedItem{rec: rec, plain: pass})
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if len(added) == 0 {
		return errors.New("no proxy entries found in file")
	}

	if *doCheck {
		sem := make(chan struct{}, 6)
		var wg sync.WaitGroup
		for i := range added {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				r := added[i].rec
				res := proxyfwd.ProbeUpstream(context.Background(), proxyfwd.UpstreamConfig{
					Scheme:   r.Scheme,
					Host:     r.Host,
					Port:     r.Port,
					Username: r.Username,
					Password: added[i].plain,
				}, *probeURL)
				if res.OK {
					added[i].rec.ExitIP = res.ExitIP
					added[i].rec.ExitCountry = res.Country
					added[i].rec.ExitTimezone = res.Timezone
					added[i].rec.LastCheckedAt = time.Now().UTC().Format(time.RFC3339)
				}
			}(i)
		}
		wg.Wait()
	}

	pub := make([]store.PublicProxy, 0, len(added))
	for _, it := range added {
		list = append(list, it.rec)
		pub = append(pub, it.rec.Public())
	}
	if err := st.SaveProxies(list); err != nil {
		return err
	}

	if jsonOut {
		return common.PrintJSON(map[string]any{"ok": true, "imported": len(pub), "proxies": pub})
	}
	fmt.Printf("Imported %d proxy(s):\n", len(pub))
	for _, p := range pub {
		fmt.Printf("  %-12s  %s://%s:%d  exit=%s  country=%s  tz=%s\n",
			p.Name, p.Scheme, p.Host, p.Port, p.ExitIP, p.ExitCountry, p.ExitTimezone)
	}
	return nil
}

func cmdProfileClone(st *store.Store, cfg store.Settings, jsonOut bool, args []string) error {
	fs := flag.NewFlagSet("profile clone", flag.ContinueOnError)
	newName := fs.String("name", "", "new profile name")
	proxyRef := fs.String("proxy", "", "override proxy ID/name for cloned profile")
	if err := parseFlagsFlexible(fs, args); err != nil {
		return err
	}
	if fs.NArg() < 1 || strings.TrimSpace(*newName) == "" {
		return errors.New("usage: browserforge profile clone --name <new-name> [--proxy <p>] <src-id|name>")
	}
	if _, err := st.FindProfile(strings.TrimSpace(*newName)); err == nil {
		return fmt.Errorf("profile name %q already exists", strings.TrimSpace(*newName))
	}
	src, err := st.FindProfile(fs.Arg(0))
	if err != nil {
		return err
	}
	proxyID := src.ProxyID
	if *proxyRef == "none" {
		proxyID = ""
	} else if *proxyRef != "" {
		pr, err := st.FindProxy(*proxyRef)
		if err != nil {
			return err
		}
		proxyID = pr.ID
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
	id, err := common.NewUUIDv4()
	if err != nil {
		return err
	}
	fp, err := fingerprint.Generate(fingerprint.GenerateParams{
		ProfileID:      id,
		Template:       src.Template,
		BrowserVersion: ver,
		Brand:          brand,
		Timezone:       src.Timezone,
		Languages:      src.Languages,
		Geolocation:    src.Geolocation,
		Host:           host,
	})
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	rec := store.ProfileRecord{
		ID:          id,
		Name:        strings.TrimSpace(*newName),
		Group:       src.Group,
		Template:    src.Template,
		ProxyID:     proxyID,
		Timezone:    src.Timezone,
		Languages:   append([]string(nil), src.Languages...),
		Geolocation: src.Geolocation,
		ExtraArgs:   append([]string(nil), src.ExtraArgs...),
		CreatedAt:   now,
		UpdatedAt:   now,
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
		return common.PrintJSON(map[string]any{"ok": true, "cloned_from": src.ID, "profile": rec, "fingerprint_checksum": fp.Checksum})
	}
	fmt.Printf("Cloned %s -> %s (%s) with fresh seed=%s...\n", src.Name, rec.Name, rec.ID, fp.Seed[:8])
	return nil
}
