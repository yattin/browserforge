package fingerprint

import (
	"fmt"
	"regexp"
	"strings"
)

type CheckStatus string

const (
	StatusPass CheckStatus = "pass"
	StatusWarn CheckStatus = "warn"
	StatusFail CheckStatus = "fail"
)

type CheckItem struct {
	Code    string      `json:"code"`
	Status  CheckStatus `json:"status"`
	Message string      `json:"message"`
}

type ValidationReport struct {
	OK      bool        `json:"ok"`
	Summary string      `json:"summary"`
	Items   []CheckItem `json:"items"`
}

type ValidationContext struct {
	Host           HostProfile
	KernelVersion  string
	ProxyCountry   string
	ProxyTimezone  string
	HasProxy       bool
	FileReadOnly   bool
	ExpectedID     string
}

var chromeMajorRe = regexp.MustCompile(`Chrome/(\d+)\.`)

// ValidateConsistency runs the 9 anti-detect consistency checks against a fingerprint.
func ValidateConsistency(fp *FingerprintData, ctx ValidationContext) ValidationReport {
	items := make([]CheckItem, 0, 9)

	// 1. Checksum & schema integrity
	sum, err := ComputeChecksum(fp)
	if err != nil || sum != fp.Checksum || fp.Algorithm != Algorithm || fp.Version != FingerprintVersion {
		items = append(items, CheckItem{Code: "fp_integrity", Status: StatusFail, Message: "Fingerprint checksum or algorithm is invalid"})
	} else if ctx.ExpectedID != "" && fp.ProfileID != ctx.ExpectedID {
		items = append(items, CheckItem{Code: "fp_integrity", Status: StatusFail, Message: "Fingerprint profile_id does not match profile"})
	} else {
		items = append(items, CheckItem{Code: "fp_integrity", Status: StatusPass, Message: "beryl-v1 SHA-256 checksum verified"})
	}

	// 2. Host OS match
	tmpl, err := ParseTemplateID(fp.Template)
	if err != nil {
		items = append(items, CheckItem{Code: "host_os_match", Status: StatusFail, Message: err.Error()})
	} else if ctx.Host.OS != "" && tmpl.OS != ctx.Host.OS {
		items = append(items, CheckItem{Code: "host_os_match", Status: StatusFail, Message: fmt.Sprintf("Template %s mismatches host OS %s", tmpl.OS, ctx.Host.OS)})
	} else {
		items = append(items, CheckItem{Code: "host_os_match", Status: StatusPass, Message: fmt.Sprintf("Template OS %s matches host", tmpl.OS)})
	}

	// 3. UA major version vs kernel major version
	if ctx.KernelVersion != "" {
		kMajor := strings.Split(ctx.KernelVersion, ".")[0]
		m := chromeMajorRe.FindStringSubmatch(fp.Navigator.UA)
		if len(m) == 2 && m[1] == kMajor {
			items = append(items, CheckItem{Code: "ua_kernel_match", Status: StatusPass, Message: fmt.Sprintf("UA Chrome/%s matches kernel %s", m[1], ctx.KernelVersion)})
		} else {
			items = append(items, CheckItem{Code: "ua_kernel_match", Status: StatusWarn, Message: fmt.Sprintf("UA major does not match kernel %s", ctx.KernelVersion)})
		}
	} else {
		items = append(items, CheckItem{Code: "ua_kernel_match", Status: StatusWarn, Message: "Kernel version unavailable for comparison"})
	}

	// 4. Hardware capability ceiling (cores & memory)
	if (ctx.Host.Cores > 0 && fp.Navigator.HardwareConcurrency > maxInt(4, ctx.Host.Cores)) ||
		(ctx.Host.MemoryGB > 0 && fp.Navigator.DeviceMemory > maxInt(4, ctx.Host.MemoryGB)) {
		items = append(items, CheckItem{Code: "hardware_bounds", Status: StatusFail, Message: "Claimed CPU/RAM exceeds physical host capacity"})
	} else {
		items = append(items, CheckItem{Code: "hardware_bounds", Status: StatusPass, Message: fmt.Sprintf("CPU=%d RAM=%dGB within host limits", fp.Navigator.HardwareConcurrency, fp.Navigator.DeviceMemory)})
	}

	// 5. Screen geometry bounds
	if fp.Screen.Width <= 0 || fp.Screen.Height <= 0 || fp.Screen.AvailHeight > fp.Screen.Height ||
		(ctx.Host.ScreenWidth > 0 && fp.Screen.Width > ctx.Host.ScreenWidth) {
		items = append(items, CheckItem{Code: "screen_bounds", Status: StatusWarn, Message: fmt.Sprintf("Screen %dx%d exceeds or conflicts with host", fp.Screen.Width, fp.Screen.Height)})
	} else {
		items = append(items, CheckItem{Code: "screen_bounds", Status: StatusPass, Message: fmt.Sprintf("Screen %dx%d valid", fp.Screen.Width, fp.Screen.Height)})
	}

	// 6. WebRTC leak protection
	if fp.WebRTC.Mode == "disable_non_proxied_udp" {
		items = append(items, CheckItem{Code: "webrtc_policy", Status: StatusPass, Message: "WebRTC non-proxied UDP disabled"})
	} else {
		items = append(items, CheckItem{Code: "webrtc_policy", Status: StatusFail, Message: fmt.Sprintf("Unsafe WebRTC mode %q", fp.WebRTC.Mode)})
	}

	// 7. Locale & languages consistency
	if len(fp.Navigator.Languages) == 0 || fp.Intl.Locale != fp.Navigator.Languages[0] {
		items = append(items, CheckItem{Code: "locale_consistency", Status: StatusFail, Message: "Intl.locale does not match navigator.languages[0]"})
	} else {
		items = append(items, CheckItem{Code: "locale_consistency", Status: StatusPass, Message: fmt.Sprintf("Locale %s consistent with languages", fp.Intl.Locale)})
	}

	// 8. Proxy timezone / geo alignment
	if ctx.HasProxy && ctx.ProxyTimezone != "" && fp.Timezone != ctx.ProxyTimezone {
		items = append(items, CheckItem{Code: "proxy_tz_match", Status: StatusWarn, Message: fmt.Sprintf("Profile timezone %s differs from proxy exit timezone %s", fp.Timezone, ctx.ProxyTimezone)})
	} else if !ctx.HasProxy {
		items = append(items, CheckItem{Code: "proxy_tz_match", Status: StatusWarn, Message: "No proxy bound (direct connection exposes host IP)"})
	} else {
		items = append(items, CheckItem{Code: "proxy_tz_match", Status: StatusPass, Message: fmt.Sprintf("Timezone %s aligned with proxy", fp.Timezone)})
	}

	// 9. Read-only fingerprint file lock
	if ctx.FileReadOnly {
		items = append(items, CheckItem{Code: "fp_readonly_lock", Status: StatusPass, Message: "fingerprint.json is locked read-only (0444)"})
	} else {
		items = append(items, CheckItem{Code: "fp_readonly_lock", Status: StatusWarn, Message: "fingerprint.json is not marked read-only"})
	}

	fails, warns := 0, 0
	for _, it := range items {
		switch it.Status {
		case StatusFail:
			fails++
		case StatusWarn:
			warns++
		}
	}
	return ValidationReport{
		OK:      fails == 0,
		Summary: fmt.Sprintf("%d pass, %d warn, %d fail", len(items)-fails-warns, warns, fails),
		Items:   items,
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
