package kernel

import (
	"strings"
	"testing"
)

func TestValidateExtraArgsBlocksDangerousFlags(t *testing.T) {
	badArgs := []string{
		"--no-sandbox",
		"--remote-debugging-port=9222",
		"--load-extension=C:/evil",
		"--gpu-launcher=calc.exe",
		"--proxy-server=http://evil:8080",
		"--user-data-dir=C:/other",
		"--beryl-profile=fake",
		"--disable-web-security",
	}
	for _, arg := range badArgs {
		if err := ValidateExtraArgs([]string{arg}); err == nil {
			t.Fatalf("expected dangerous flag %q to be rejected", arg)
		}
	}
	if err := ValidateExtraArgs([]string{"--window-size=1280,800", "--mute-audio"}); err != nil {
		t.Fatalf("expected benign flags to pass, got %v", err)
	}
}

func TestBuildLaunchArgsBeryl(t *testing.T) {
	args, err := BuildLaunchArgs(LaunchOptions{
		Kernel:      KernelInfo{Kind: "beryl", Brand: "Google Chrome", ExePath: `C:\Beryl\chrome.exe`},
		ProfileID:   "11111111-2222-4333-8444-555555555555",
		UserDataDir: `C:\Data\userdata`,
		CacheDir:    `C:\Data\cache`,
		ProxyPort:   18080,
		Headless:    true,
	})
	if err != nil {
		t.Fatalf("BuildLaunchArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--beryl-profile=11111111-2222-4333-8444-555555555555",
		"--remote-debugging-port=0",
		"--disable-backgrounding-occluded-windows",
		"--disable-renderer-backgrounding",
		"--disable-background-timer-throttling",
		"--disable-features=CalculateNativeWinOcclusion",
		"--webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--proxy-server=http://127.0.0.1:18080",
		"--disable-encryption",
		"--headless=new",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing expected arg %q in %s", want, joined)
		}
	}
}

func TestBuildLaunchArgsMergesDisableFeatures(t *testing.T) {
	args, err := BuildLaunchArgs(LaunchOptions{
		Kernel:      KernelInfo{Kind: "edge", Brand: "Microsoft Edge", ExePath: `C:\Edge\msedge.exe`},
		ProfileID:   "11111111-2222-4333-8444-555555555555",
		UserDataDir: `C:\Data\userdata`,
		CacheDir:    `C:\Data\cache`,
		ExtraArgs:   []string{"--disable-features=Translate,CalculateNativeWinOcclusion", "--mute-audio"},
	})
	if err != nil {
		t.Fatalf("BuildLaunchArgs: %v", err)
	}
	var featFlags []string
	for _, a := range args {
		if strings.HasPrefix(a, "--disable-features=") {
			featFlags = append(featFlags, a)
		}
	}
	if len(featFlags) != 1 {
		t.Fatalf("expected exactly 1 --disable-features flag, got %d: %v", len(featFlags), featFlags)
	}
	want := "--disable-features=CalculateNativeWinOcclusion,msEdgeAccountConsistency,msEdgeSync,msEdgeOnRamp,Translate"
	if featFlags[0] != want {
		t.Fatalf("merged --disable-features = %q, want %q", featFlags[0], want)
	}
}

func TestValidateStartURL(t *testing.T) {
	for _, bad := range []string{
		"--no-sandbox",
		"-gpu-launcher=calc.exe",
		"file:///C:/Windows/win.ini",
		"javascript:alert(1)",
		"chrome://settings",
		"http://",
	} {
		if err := ValidateStartURL(bad); err == nil {
			t.Fatalf("expected bad StartURL %q to be rejected", bad)
		}
	}
	for _, good := range []string{"", "about:blank", "https://example.com/a?b=1", "http://127.0.0.1:8080/"} {
		if err := ValidateStartURL(good); err != nil {
			t.Fatalf("expected good StartURL %q to pass, got %v", good, err)
		}
	}
}
