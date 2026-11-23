package kernel

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// DangerousFlagPrefixes are blocked from user-supplied --extra-args to prevent sandbox escape or proxy/debugging hijack.
var DangerousFlagPrefixes = []string{
	"--no-sandbox",
	"--disable-web-security",
	"--disable-site-isolation-trials",
	"--remote-debugging-",
	"--user-data-dir",
	"--disk-cache-dir",
	"--proxy-server",
	"--proxy-pac-url",
	"--proxy-bypass-list",
	"--beryl-profile",
	"--load-extension",
	"--disable-extensions-except",
	"--renderer-cmd-prefix",
	"--gpu-launcher",
	"--utility-cmd-prefix",
	"--browser-subprocess-path",
	"--host-resolver-rules",
	"--ignore-certificate-errors",
}

// ValidateExtraArgs rejects dangerous Chromium flags.
func ValidateExtraArgs(args []string) error {
	for _, raw := range args {
		a := strings.TrimSpace(raw)
		if a == "" {
			continue
		}
		lower := strings.ToLower(a)
		if !strings.HasPrefix(lower, "--") {
			return fmt.Errorf("extra arg %q must start with --", a)
		}
		if strings.Contains(lower, "-launcher") {
			return fmt.Errorf("disallowed dangerous flag %q", a)
		}
		for _, bad := range DangerousFlagPrefixes {
			if lower == bad || strings.HasPrefix(lower, bad+"=") || strings.HasPrefix(lower, bad) && strings.HasSuffix(bad, "-") {
				return fmt.Errorf("disallowed dangerous flag %q", a)
			}
		}
	}
	return nil
}

type LaunchOptions struct {
	Kernel      KernelInfo
	ProfileID   string
	UserDataDir string
	CacheDir    string
	LogFile     string
	ProxyPort   int
	Headless    bool
	StartURL    string
	ExtraArgs   []string
}

type LaunchResult struct {
	PID       int
	DebugPort int
	WSPath    string
}

// ValidateStartURL blocks Chromium flag injection via --url and restricts schemes to http/https/about:blank.
func ValidateStartURL(raw string) error {
	s := strings.TrimSpace(raw)
	if s == "" || s == "about:blank" {
		return nil
	}
	if strings.HasPrefix(s, "-") {
		return fmt.Errorf("disallowed start URL %q (must not start with -)", raw)
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("invalid start URL %q: %w", raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("disallowed start URL scheme %q (expected http, https, or about:blank)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("start URL %q missing host", raw)
	}
	return nil
}

// BuildLaunchArgs constructs the isolated Chromium command-line flags.
func BuildLaunchArgs(opts LaunchOptions) ([]string, error) {
	if err := ValidateExtraArgs(opts.ExtraArgs); err != nil {
		return nil, err
	}
	if err := ValidateStartURL(opts.StartURL); err != nil {
		return nil, err
	}
	args := []string{
		"--user-data-dir=" + opts.UserDataDir,
		"--disk-cache-dir=" + opts.CacheDir,
		"--beryl-profile=" + opts.ProfileID,
		"--remote-debugging-port=0",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-background-networking",
		"--disable-backgrounding-occluded-windows",
		"--disable-renderer-backgrounding",
		"--disable-background-timer-throttling",
		"--disable-sync",
		"--metrics-recording-only",
		"--webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--force-webrtc-ip-handling-policy",
	}
	disabledFeatures := []string{"CalculateNativeWinOcclusion"}
	seenFeature := map[string]bool{"CalculateNativeWinOcclusion": true}
	addDisabledFeatures := func(csv string) {
		for _, part := range strings.Split(csv, ",") {
			f := strings.TrimSpace(part)
			if f == "" || seenFeature[f] {
				continue
			}
			seenFeature[f] = true
			disabledFeatures = append(disabledFeatures, f)
		}
	}
	if opts.Kernel.Kind == "beryl" {
		args = append(args,
			"--disable-encryption",
			"--disable-machine-id",
			"--ignore-gpu-blocklist",
			"--enable-unsafe-swiftshader",
		)
	}
	if opts.Kernel.Kind == "edge" {
		addDisabledFeatures("msEdgeAccountConsistency,msEdgeSync,msEdgeOnRamp")
	}
	if opts.ProxyPort > 0 {
		args = append(args, fmt.Sprintf("--proxy-server=http://127.0.0.1:%d", opts.ProxyPort))
	}
	if opts.Headless {
		args = append(args, "--headless=new")
	}
	extraClean := make([]string, 0, len(opts.ExtraArgs))
	for _, a := range opts.ExtraArgs {
		t := strings.TrimSpace(a)
		if t == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(t), "--disable-features=") {
			if eq := strings.IndexByte(t, '='); eq >= 0 {
				addDisabledFeatures(t[eq+1:])
			}
			continue
		}
		extraClean = append(extraClean, t)
	}
	args = append(args, "--disable-features="+strings.Join(disabledFeatures, ","))
	args = append(args, extraClean...)
	if opts.StartURL != "" {
		args = append(args, opts.StartURL)
	} else {
		args = append(args, "about:blank")
	}
	return args, nil
}

// Launch starts the browser process and waits for DevToolsActivePort.
func Launch(opts LaunchOptions, timeout time.Duration) (*LaunchResult, error) {
	args, err := BuildLaunchArgs(opts)
	if err != nil {
		return nil, err
	}

	// Remove stale DevToolsActivePort before launch so we never read a previous session's port.
	portFile := filepath.Join(opts.UserDataDir, "DevToolsActivePort")
	_ = os.Remove(portFile)

	cmd := exec.Command(opts.Kernel.ExePath, args...)
	if opts.LogFile != "" {
		if f, err := os.OpenFile(opts.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
			cmd.Stdout = f
			cmd.Stderr = f
			defer f.Close()
		}
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start browser %s: %w", opts.Kernel.ExePath, err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Release()

	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !IsProcessAlive(pid) {
			return nil, fmt.Errorf("browser process %d exited prematurely before DevTools became ready", pid)
		}
		if raw, err := os.ReadFile(portFile); err == nil {
			lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
			if len(lines) >= 1 {
				port, err := strconv.Atoi(strings.TrimSpace(lines[0]))
				if err == nil && port > 0 {
					wsPath := ""
					if len(lines) >= 2 {
						wsPath = strings.TrimSpace(lines[1])
					}
					return &LaunchResult{
						PID:       pid,
						DebugPort: port,
						WSPath:    wsPath,
					}, nil
				}
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	_ = TerminateProcess(pid)
	return nil, fmt.Errorf("timed out waiting for DevToolsActivePort (pid=%d)", pid)
}
