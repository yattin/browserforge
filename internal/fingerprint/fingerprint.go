package fingerprint

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"browserforge/internal/common"
)

const (
	FingerprintVersion = 1
	Algorithm          = "beryl-v1"
	taskbarHeight      = 40
)

var seedHexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

type BrandVersion struct {
	Brand   string `json:"brand"`
	Version string `json:"version"`
}

type UACH struct {
	Brands          []BrandVersion `json:"brands"`
	FullVersionList []BrandVersion `json:"fullVersionList"`
	Platform        string         `json:"platform"`
	PlatformVersion string         `json:"platformVersion"`
	Architecture    string         `json:"architecture"`
	Bitness         string         `json:"bitness"`
	Model           string         `json:"model"`
	Mobile          bool           `json:"mobile"`
	Wow64           bool           `json:"wow64"`
}

type NavigatorSpec struct {
	UA                  string   `json:"ua"`
	UACH                UACH     `json:"ua_ch"`
	Platform            string   `json:"platform"`
	HardwareConcurrency int      `json:"hardwareConcurrency"`
	DeviceMemory        int      `json:"deviceMemory"`
	Languages           []string `json:"languages"`
}

type ScreenSpec struct {
	Width       int `json:"width"`
	Height      int `json:"height"`
	AvailWidth  int `json:"availWidth"`
	AvailHeight int `json:"availHeight"`
	ColorDepth  int `json:"colorDepth"`
	PixelDepth  int `json:"pixelDepth"`
}

type ModeSpec struct {
	Mode string `json:"mode"`
}

type WebGLSpec struct {
	Vendor      string         `json:"vendor"`
	Renderer    string         `json:"renderer"`
	Params      map[string]any `json:"params"`
	RenderNoise string         `json:"render_noise"`
}

type FontsSpec struct {
	Mode      string   `json:"mode"`
	Allowlist []string `json:"allowlist"`
}

type GeolocationSetting struct {
	Mode      string   `json:"mode"`
	Latitude  *float64 `json:"latitude,omitempty"`
	Longitude *float64 `json:"longitude,omitempty"`
	Accuracy  *float64 `json:"accuracy,omitempty"`
}

type WebGPUSpec struct {
	Vendor       string `json:"vendor"`
	Architecture string `json:"architecture"`
	Device       string `json:"device"`
}

type IntlSpec struct {
	Locale string `json:"locale"`
}

// FingerprintData matches the Beryl C++ kernel's fingerprint.json contract.
type FingerprintData struct {
	Version      int                `json:"version"`
	Algorithm    string             `json:"algorithm"`
	ProfileID    string             `json:"profile_id"`
	CreatedAt    string             `json:"created_at"`
	Seed         string             `json:"seed"`
	Template     string             `json:"template"`
	Navigator    NavigatorSpec      `json:"navigator"`
	Intl         IntlSpec           `json:"intl"`
	Screen       ScreenSpec         `json:"screen"`
	Canvas       ModeSpec           `json:"canvas"`
	WebGL        WebGLSpec          `json:"webgl"`
	Audio        ModeSpec           `json:"audio"`
	TextMetrics  ModeSpec           `json:"text_metrics"`
	Fonts        FontsSpec          `json:"fonts"`
	Timezone     string             `json:"timezone"`
	Geolocation  GeolocationSetting `json:"geolocation"`
	WebRTC       ModeSpec           `json:"webrtc"`
	WebGPU       WebGPUSpec         `json:"webgpu"`
	SpeechVoices ModeSpec           `json:"speech_voices"`
	Plugins      ModeSpec           `json:"plugins"`
	MediaDevices ModeSpec           `json:"mediaDevices"`
	Checksum     string             `json:"checksum"`
}

type GenerateParams struct {
	ProfileID      string
	Template       string
	BrowserVersion string
	Brand          string
	Timezone       string
	Languages      []string
	Geolocation    *GeolocationSetting
	Host           HostProfile
	Now            string
	Seed           string
}

type seededChooser struct {
	key     []byte
	counter uint32
}

func newSeededChooser(seedHex string) (*seededChooser, error) {
	key, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, err
	}
	return &seededChooser{key: key}, nil
}

func (c *seededChooser) nextU32() uint32 {
	mac := hmac.New(sha256.New, c.key)
	_, _ = mac.Write([]byte(fmt.Sprintf("beryl/v1/choice/%d", c.counter)))
	c.counter++
	sum := mac.Sum(nil)
	return binary.BigEndian.Uint32(sum[:4])
}

func pickSlice[T any](c *seededChooser, arr []T) T {
	return arr[int(c.nextU32())%len(arr)]
}

func subsetSlice[T any](c *seededChooser, arr []T, minN, maxN int) []T {
	if len(arr) == 0 || maxN <= 0 {
		return nil
	}
	if minN > len(arr) {
		minN = len(arr)
	}
	if maxN > len(arr) {
		maxN = len(arr)
	}
	count := minN
	if maxN > minN {
		count = minN + int(c.nextU32())%(maxN-minN+1)
	}
	pool := append([]T(nil), arr...)
	out := make([]T, 0, count)
	for len(out) < count && len(pool) > 0 {
		idx := int(c.nextU32()) % len(pool)
		out = append(out, pool[idx])
		pool = append(pool[:idx], pool[idx+1:]...)
	}
	return out
}

// Generate creates a new deterministic beryl-v1 fingerprint.
func Generate(p GenerateParams) (*FingerprintData, error) {
	tmpl, err := ParseTemplateID(p.Template)
	if err != nil {
		return nil, err
	}
	if p.Host.OS != "" && tmpl.OS != p.Host.OS {
		return nil, fmt.Errorf("template %s does not match host OS %s (cross-OS spoofing is disabled)", p.Template, p.Host.OS)
	}
	if strings.TrimSpace(p.BrowserVersion) == "" {
		return nil, fmt.Errorf("browser version is required to generate UA")
	}
	if len(p.Languages) == 0 {
		return nil, fmt.Errorf("languages cannot be empty")
	}

	seed := p.Seed
	if seed == "" {
		seed, err = common.RandomHex(32)
		if err != nil {
			return nil, err
		}
	}
	if !seedHexRe.MatchString(seed) {
		return nil, fmt.Errorf("seed must be 64 lowercase hex characters")
	}

	chooser, err := newSeededChooser(seed)
	if err != nil {
		return nil, err
	}

	major := strings.Split(p.BrowserVersion, ".")[0]
	brand := p.Brand
	if brand == "" {
		brand = "Google Chrome"
	}

	maxCores := p.Host.Cores
	if maxCores < 4 {
		maxCores = 4
	}
	var cores []int
	for _, n := range CorePresets {
		if n <= maxCores {
			cores = append(cores, n)
		}
	}
	if len(cores) == 0 {
		cores = []int{4}
	}

	maxMem := p.Host.MemoryGB
	if maxMem < 4 {
		maxMem = 4
	}
	var mems []int
	for _, n := range MemoryPresets {
		if n <= maxMem {
			mems = append(mems, n)
		}
	}
	if len(mems) == 0 {
		mems = []int{4}
	}

	hostW, hostH := p.Host.ScreenWidth, p.Host.ScreenHeight
	if hostW < 800 || hostH < 600 {
		hostW, hostH = 1920, 1080
	}
	var screens [][2]int
	for _, s := range ScreenPresets {
		if s[0] <= hostW && s[1] <= hostH {
			screens = append(screens, s)
		}
	}
	var sw, sh int
	if len(screens) > 0 {
		chosen := pickSlice(chooser, screens)
		sw, sh = chosen[0], chosen[1]
	} else {
		sw, sh = hostW, hostH
	}

	brands := []BrandVersion{{Brand: brand, Version: major}}
	if brand != "Chromium" {
		brands = append(brands, BrandVersion{Brand: "Chromium", Version: major})
	}
	fullVersions := make([]BrandVersion, len(brands))
	for i, b := range brands {
		fullVersions[i] = BrandVersion{Brand: b.Brand, Version: p.BrowserVersion}
	}

	baseFonts := append([]string(nil), BaseFonts...)
	optFonts := append([]string(nil), OptionalFonts...)
	if len(p.Host.InstalledFonts) > 0 {
		var fb, fo []string
		for _, f := range BaseFonts {
			if p.Host.InstalledFonts[f] {
				fb = append(fb, f)
			}
		}
		for _, f := range OptionalFonts {
			if p.Host.InstalledFonts[f] {
				fo = append(fo, f)
			}
		}
		if len(fb) > 0 {
			baseFonts = fb
		}
		optFonts = fo
	}
	minOpt, maxOpt := 3, 8
	if len(optFonts) < minOpt {
		minOpt = len(optFonts)
	}
	if len(optFonts) < maxOpt {
		maxOpt = len(optFonts)
	}
	pickedOpt := subsetSlice(chooser, optFonts, minOpt, maxOpt)
	allowlist := append(baseFonts, pickedOpt...)
	sort.Strings(allowlist)

	uaSuffix := ""
	if brand == "Microsoft Edge" {
		uaSuffix = fmt.Sprintf(" Edg/%s.0.0.0", major)
	}
	now := p.Now
	if now == "" {
		now = time.Now().UTC().Format(time.RFC3339Nano)
	}
	geo := GeolocationSetting{Mode: "deny"}
	if p.Geolocation != nil {
		geo = *p.Geolocation
	}
	platformVer := p.Host.PlatformVersion
	if platformVer == "" {
		platformVer = "15.0.0"
	}
	tz := p.Timezone
	if tz == "" {
		tz = "UTC"
	}

	fp := &FingerprintData{
		Version:   FingerprintVersion,
		Algorithm: Algorithm,
		ProfileID: p.ProfileID,
		CreatedAt: now,
		Seed:      seed,
		Template:  p.Template,
		Navigator: NavigatorSpec{
			UA: fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s.0.0.0 Safari/537.36%s", major, uaSuffix),
			UACH: UACH{
				Brands:          brands,
				FullVersionList: fullVersions,
				Platform:        "Windows",
				PlatformVersion: platformVer,
				Architecture:    "x86",
				Bitness:         "64",
				Model:           "",
				Mobile:          false,
				Wow64:           false,
			},
			Platform:            "Win32",
			HardwareConcurrency: pickSlice(chooser, cores),
			DeviceMemory:        pickSlice(chooser, mems),
			Languages:           append([]string(nil), p.Languages...),
		},
		Intl: IntlSpec{Locale: p.Languages[0]},
		Screen: ScreenSpec{
			Width:       sw,
			Height:      sh,
			AvailWidth:  sw,
			AvailHeight: sh - taskbarHeight,
			ColorDepth:  24,
			PixelDepth:  24,
		},
		Canvas: ModeSpec{Mode: "seeded_noise"},
		WebGL: WebGLSpec{
			Vendor:      tmpl.Preset.Vendor,
			Renderer:    pickSlice(chooser, tmpl.Preset.Renderers),
			Params:      tmpl.Preset.Params,
			RenderNoise: "seeded_noise",
		},
		Audio:        ModeSpec{Mode: "seeded_noise"},
		TextMetrics:  ModeSpec{Mode: "seeded_noise"},
		Fonts:        FontsSpec{Mode: "allowlist", Allowlist: allowlist},
		Timezone:     tz,
		Geolocation:  geo,
		WebRTC:       ModeSpec{Mode: "disable_non_proxied_udp"},
		WebGPU:       WebGPUSpec{Vendor: tmpl.Preset.WebGPU.Vendor, Architecture: tmpl.Preset.WebGPU.Architecture, Device: ""},
		SpeechVoices: ModeSpec{Mode: "template"},
		Plugins:      ModeSpec{Mode: "template"},
		MediaDevices: ModeSpec{Mode: "template"},
	}

	checksum, err := ComputeChecksum(fp)
	if err != nil {
		return nil, err
	}
	fp.Checksum = checksum
	return fp, nil
}

// WithEditable returns an updated copy with modified timezone/languages/geolocation and recomputed checksum.
func (fp *FingerprintData) WithEditable(timezone string, languages []string, geo *GeolocationSetting) (*FingerprintData, error) {
	raw, err := json.Marshal(fp)
	if err != nil {
		return nil, err
	}
	var next FingerprintData
	if err := json.Unmarshal(raw, &next); err != nil {
		return nil, err
	}
	if timezone != "" {
		next.Timezone = timezone
	}
	if len(languages) > 0 {
		next.Navigator.Languages = append([]string(nil), languages...)
		next.Intl.Locale = languages[0]
	}
	if geo != nil {
		next.Geolocation = *geo
	}
	sum, err := ComputeChecksum(&next)
	if err != nil {
		return nil, err
	}
	next.Checksum = sum
	return &next, nil
}

// ValidateIntegrity mirrors the Beryl C++ kernel's fail-closed fingerprint.json verification.
func ValidateIntegrity(raw []byte, expectedProfileID string) (*FingerprintData, error) {
	var fp FingerprintData
	if err := json.Unmarshal(raw, &fp); err != nil {
		return nil, fmt.Errorf("invalid fingerprint JSON: %w", err)
	}
	if fp.Version != FingerprintVersion {
		return nil, fmt.Errorf("unsupported fingerprint version %d", fp.Version)
	}
	if fp.Algorithm != Algorithm {
		return nil, fmt.Errorf("unsupported fingerprint algorithm %q (expected %q)", fp.Algorithm, Algorithm)
	}
	if fp.ProfileID == "" {
		return nil, fmt.Errorf("missing profile_id")
	}
	if expectedProfileID != "" && fp.ProfileID != expectedProfileID {
		return nil, fmt.Errorf("profile_id mismatch: got %q, want %q", fp.ProfileID, expectedProfileID)
	}
	if !seedHexRe.MatchString(fp.Seed) {
		return nil, fmt.Errorf("invalid seed format")
	}
	if fp.Checksum == "" {
		return nil, fmt.Errorf("missing checksum")
	}
	// Verify checksum against raw JSON map so unknown fields also participate just like C++.
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var generic map[string]any
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	expectedSum, err := ComputeChecksum(generic)
	if err != nil {
		return nil, err
	}
	if expectedSum != fp.Checksum {
		return nil, fmt.Errorf("checksum mismatch: computed %s, file has %s", expectedSum, fp.Checksum)
	}
	return &fp, nil
}

// MarshalIndented serializes FingerprintData without HTML escaping.
func (fp *FingerprintData) MarshalIndented() ([]byte, error) {
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(fp); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}
