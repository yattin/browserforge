package fingerprint

import (
	"fmt"
	"regexp"
)

// BaseFonts are standard Windows system fonts.
var BaseFonts = []string{
	"Arial", "Arial Black", "Bahnschrift", "Calibri", "Cambria", "Cambria Math", "Candara", "Comic Sans MS",
	"Consolas", "Constantia", "Corbel", "Courier New", "Ebrima", "Franklin Gothic Medium", "Gabriola", "Gadugi",
	"Georgia", "Impact", "Ink Free", "Javanese Text", "Leelawadee UI", "Lucida Console", "Lucida Sans Unicode",
	"Malgun Gothic", "Marlett", "Microsoft Himalaya", "Microsoft JhengHei", "Microsoft New Tai Lue",
	"Microsoft PhagsPa", "Microsoft Sans Serif", "Microsoft Tai Le", "Microsoft YaHei", "Microsoft Yi Baiti",
	"MingLiU-ExtB", "Mongolian Baiti", "MS Gothic", "MV Boli", "Myanmar Text", "Nirmala UI", "Palatino Linotype",
	"Segoe MDL2 Assets", "Segoe Print", "Segoe Script", "Segoe UI", "Segoe UI Emoji", "Segoe UI Historic",
	"Segoe UI Symbol", "SimSun", "Sitka", "Sylfaen", "Symbol", "Tahoma", "Times New Roman", "Trebuchet MS",
	"Verdana", "Webdings", "Wingdings", "Yu Gothic",
}

// OptionalFonts are deterministically sampled per profile seed to create realistic variation.
var OptionalFonts = []string{
	"SimHei", "KaiTi", "FangSong", "DengXian", "NSimSun", "Microsoft YaHei UI", "Segoe UI Variable",
	"Cascadia Code", "Cascadia Mono", "HoloLens MDL2 Assets", "Segoe Fluent Icons", "Arial Nova",
	"Georgia Pro", "Gill Sans Nova", "Neue Haas Grotesk Text Pro", "Rockwell Nova", "Verdana Pro",
}

// ScreenPresets are realistic Windows desktop resolutions.
var ScreenPresets = [][2]int{
	{1920, 1080}, {2560, 1440}, {1600, 900}, {1536, 864},
	{1366, 768}, {1440, 900}, {1680, 1050}, {1920, 1200},
}

var (
	CorePresets   = []int{4, 6, 8, 12, 16}
	MemoryPresets = []int{4, 8}
)

type GPUPreset struct {
	Label     string
	Vendor    string
	Renderers []string
	Params    map[string]any
	WebGPU    struct {
		Vendor       string
		Architecture string
	}
}

var GPUPresets = map[string]GPUPreset{
	"nvidia": {
		Label:  "NVIDIA",
		Vendor: "Google Inc. (NVIDIA)",
		Renderers: []string{
			"ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)",
			"ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 SUPER Direct3D11 vs_5_0 ps_5_0, D3D11)",
			"ANGLE (NVIDIA, NVIDIA GeForce RTX 2060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
			"ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
			"ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 Direct3D11 vs_5_0 ps_5_0, D3D11)",
			"ANGLE (NVIDIA, NVIDIA GeForce RTX 4060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
		},
		Params: map[string]any{
			"MAX_TEXTURE_SIZE":      32768,
			"MAX_RENDERBUFFER_SIZE": 32768,
			"MAX_VIEWPORT_DIMS":     []int{32768, 32768},
		},
		WebGPU: struct {
			Vendor       string
			Architecture string
		}{Vendor: "nvidia", Architecture: ""},
	},
	"intel": {
		Label:  "Intel",
		Vendor: "Google Inc. (Intel)",
		Renderers: []string{
			"ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)",
			"ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)",
			"ANGLE (Intel, Intel(R) UHD Graphics 770 Direct3D11 vs_5_0 ps_5_0, D3D11)",
			"ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)",
		},
		Params: map[string]any{
			"MAX_TEXTURE_SIZE":      16384,
			"MAX_RENDERBUFFER_SIZE": 16384,
			"MAX_VIEWPORT_DIMS":     []int{16384, 16384},
		},
		WebGPU: struct {
			Vendor       string
			Architecture string
		}{Vendor: "intel", Architecture: ""},
	},
	"amd": {
		Label:  "AMD",
		Vendor: "Google Inc. (AMD)",
		Renderers: []string{
			"ANGLE (AMD, AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)",
			"ANGLE (AMD, AMD Radeon RX 580 2048SP Direct3D11 vs_5_0 ps_5_0, D3D11)",
			"ANGLE (AMD, AMD Radeon RX 6600 Direct3D11 vs_5_0 ps_5_0, D3D11)",
			"ANGLE (AMD, AMD Radeon RX 6700 XT Direct3D11 vs_5_0 ps_5_0, D3D11)",
		},
		Params: map[string]any{
			"MAX_TEXTURE_SIZE":      16384,
			"MAX_RENDERBUFFER_SIZE": 16384,
			"MAX_VIEWPORT_DIMS":     []int{16384, 16384},
		},
		WebGPU: struct {
			Vendor       string
			Architecture string
		}{Vendor: "amd", Architecture: ""},
	},
}

type ParsedTemplate struct {
	ID     string
	OS     string
	GPU    string
	Preset GPUPreset
}

var templateRe = regexp.MustCompile(`^(win10|win11)_x64_(nvidia|intel|amd)$`)

// ParseTemplateID validates and resolves a template identifier.
func ParseTemplateID(id string) (*ParsedTemplate, error) {
	m := templateRe.FindStringSubmatch(id)
	if len(m) != 3 {
		return nil, fmt.Errorf("unknown fingerprint template %q (expected win10_x64_* or win11_x64_*)", id)
	}
	preset, ok := GPUPresets[m[2]]
	if !ok {
		return nil, fmt.Errorf("unknown GPU preset %q", m[2])
	}
	return &ParsedTemplate{
		ID:     id,
		OS:     m[1],
		GPU:    m[2],
		Preset: preset,
	}, nil
}

// DefaultTemplateID returns the recommended template for the detected host OS and GPU.
func DefaultTemplateID(hostOS, gpu string) string {
	osTag := "win11"
	if hostOS == "win10" {
		osTag = "win10"
	}
	if _, ok := GPUPresets[gpu]; !ok {
		gpu = "nvidia"
	}
	return osTag + "_x64_" + gpu
}
