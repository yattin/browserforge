package fingerprint

import (
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"browserforge/internal/common"
)

// HostProfile captures real host hardware capabilities so generated fingerprints never overclaim.
type HostProfile struct {
	OS              string          `json:"os"`
	PlatformVersion string          `json:"platform_version"`
	Cores           int             `json:"cores"`
	MemoryGB        int             `json:"memory_gb"`
	ScreenWidth     int             `json:"screen_width"`
	ScreenHeight    int             `json:"screen_height"`
	GPUVendor       string          `json:"gpu_vendor"`
	InstalledFonts  map[string]bool `json:"-"`
}

// DetectHost inspects the local machine with safe defaults when commands are unavailable.
func DetectHost() HostProfile {
	hp := HostProfile{
		OS:              "win11",
		PlatformVersion: "15.0.0",
		Cores:           runtime.NumCPU(),
		MemoryGB:        16,
		ScreenWidth:     1920,
		ScreenHeight:    1080,
		GPUVendor:       "nvidia",
		InstalledFonts:  map[string]bool{},
	}
	if hp.Cores < 4 {
		hp.Cores = 4
	}
	if runtime.GOOS != "windows" {
		return hp
	}

	// Best-effort single PowerShell call to detect build number, RAM, largest real display resolution, and physical GPU vendor.
	script := `
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
$vcs = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue)
$build = if ($os) { [int]$os.BuildNumber } else { 22631 }
$memGb = if ($cs) { [int][math]::Max(4, [math]::Round($cs.TotalPhysicalMemory / 1GB)) } else { 16 }
$bestRes = $vcs | Where-Object { $_.CurrentHorizontalResolution -ge 1366 -and $_.CurrentVerticalResolution -ge 768 } |
  Sort-Object @{Expression={[int]$_.CurrentHorizontalResolution * [int]$_.CurrentVerticalResolution}; Descending=$true} |
  Select-Object -First 1
$w = if ($bestRes) { [int]$bestRes.CurrentHorizontalResolution } else { 1920 }
$h = if ($bestRes) { [int]$bestRes.CurrentVerticalResolution } else { 1080 }
$physGpu = $vcs | Where-Object { "$($_.Name) $($_.AdapterCompatibility)" -match 'NVIDIA|AMD|Radeon|Intel' } | Select-Object -First 1
$gpu = if ($physGpu) { "$($physGpu.Name) $($physGpu.AdapterCompatibility)" } elseif ($vcs.Count -gt 0) { "$($vcs[0].Name) $($vcs[0].AdapterCompatibility)" } else { "NVIDIA" }
Write-Output "$build|$memGb|$w|$h|$gpu"
`
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	common.HideCmdWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		return hp
	}
	line := strings.TrimSpace(string(out))
	parts := strings.SplitN(line, "|", 5)
	if len(parts) < 5 {
		return hp
	}
	if build, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil {
		if build >= 22000 {
			hp.OS = "win11"
			hp.PlatformVersion = "15.0.0"
		} else {
			hp.OS = "win10"
			hp.PlatformVersion = "10.0.0"
		}
	}
	if mem, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil && mem >= 4 {
		hp.MemoryGB = mem
	}
	if w, err := strconv.Atoi(strings.TrimSpace(parts[2])); err == nil && w >= 1366 {
		hp.ScreenWidth = w
	}
	if h, err := strconv.Atoi(strings.TrimSpace(parts[3])); err == nil && h >= 768 {
		hp.ScreenHeight = h
	}
	gpuLower := strings.ToLower(parts[4])
	switch {
	case strings.Contains(gpuLower, "nvidia"):
		hp.GPUVendor = "nvidia"
	case strings.Contains(gpuLower, "amd"), strings.Contains(gpuLower, "radeon"):
		hp.GPUVendor = "amd"
	case strings.Contains(gpuLower, "intel"):
		hp.GPUVendor = "intel"
	}
	return hp
}
