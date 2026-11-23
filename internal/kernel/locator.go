package kernel

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type KernelInfo struct {
	Kind    string `json:"kind"`  // beryl, chrome, edge, custom
	Brand   string `json:"brand"` // Google Chrome, Microsoft Edge, Chromium
	ExePath string `json:"exe_path"`
	Version string `json:"version"`
}

// Discover finds available browser kernels ordered by priority (env/configured -> Beryl -> Chrome -> Edge).
func Discover(configuredExe string) []KernelInfo {
	type candidate struct {
		kind  string
		brand string
		path  string
	}
	var cands []candidate

	if envExe := strings.TrimSpace(os.Getenv("BROWSERFORGE_KERNEL_EXE")); envExe != "" {
		cands = append(cands, candidate{kind: classifyKind(envExe), brand: classifyBrand(envExe), path: envExe})
	}
	if strings.TrimSpace(configuredExe) != "" {
		cands = append(cands, candidate{kind: classifyKind(configuredExe), brand: classifyBrand(configuredExe), path: configuredExe})
	}

	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		cands = append(cands,
			candidate{kind: "beryl", brand: "Google Chrome", path: filepath.Join(exeDir, "kernel", "chrome.exe")},
			candidate{kind: "beryl", brand: "Google Chrome", path: filepath.Join(exeDir, "..", "kernel", "chrome.exe")},
		)
	}

	if runtime.GOOS == "windows" {
		localApp := os.Getenv("LOCALAPPDATA")
		progFiles := os.Getenv("PROGRAMFILES")
		progFiles86 := os.Getenv("PROGRAMFILES(X86)")

		if localApp != "" {
			cands = append(cands,
				candidate{kind: "beryl", brand: "Google Chrome", path: filepath.Join(localApp, "BrowserForge", "kernel", "chrome.exe")},
				candidate{kind: "beryl", brand: "Google Chrome", path: filepath.Join(localApp, "Beryl", "chrome.exe")},
			)
		}
		for _, base := range []string{progFiles, progFiles86, localApp} {
			if base == "" {
				continue
			}
			cands = append(cands,
				candidate{kind: "chrome", brand: "Google Chrome", path: filepath.Join(base, "Google", "Chrome", "Application", "chrome.exe")},
				candidate{kind: "edge", brand: "Microsoft Edge", path: filepath.Join(base, "Microsoft", "Edge", "Application", "msedge.exe")},
			)
		}
	} else {
		cands = append(cands,
			candidate{kind: "chrome", brand: "Google Chrome", path: "/usr/bin/google-chrome"},
			candidate{kind: "chrome", brand: "Chromium", path: "/usr/bin/chromium"},
			candidate{kind: "chrome", brand: "Chromium", path: "/usr/bin/chromium-browser"},
		)
	}

	seen := map[string]bool{}
	var out []KernelInfo
	for _, c := range cands {
		if c.path == "" {
			continue
		}
		abs, err := filepath.Abs(c.path)
		if err != nil {
			continue
		}
		key := strings.ToLower(abs)
		if seen[key] {
			continue
		}
		if st, err := os.Stat(abs); err != nil || st.IsDir() {
			continue
		}
		seen[key] = true
		ver := ReadExecutableVersion(abs)
		kind := c.kind
		if kind == "custom" || kind == "chrome" {
			kind = classifyKind(abs)
		}
		out = append(out, KernelInfo{
			Kind:    kind,
			Brand:   classifyBrand(abs),
			ExePath: abs,
			Version: ver,
		})
	}
	return out
}

// Resolve selects the preferred kernel (env/configured or first discovered).
func Resolve(configuredExe string) *KernelInfo {
	list := Discover(configuredExe)
	if len(list) == 0 {
		return nil
	}
	return &list[0]
}

func classifyKind(exePath string) string {
	lower := strings.ToLower(exePath)
	switch {
	case strings.Contains(lower, "msedge"):
		return "edge"
	case strings.Contains(lower, "beryl") || strings.Contains(lower, "ungoogled") || strings.Contains(lower, `\kernel\chrome.exe`):
		return "beryl"
	case strings.Contains(lower, "chrome"):
		return "chrome"
	default:
		return "custom"
	}
}

func classifyBrand(exePath string) string {
	lower := strings.ToLower(exePath)
	if strings.Contains(lower, "msedge") {
		return "Microsoft Edge"
	}
	return "Google Chrome"
}
