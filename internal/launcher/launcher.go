package launcher

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"browserforge/internal/common"
	"browserforge/internal/kernel"
	"browserforge/internal/proxyfwd"
	"browserforge/internal/store"
)

var (
	profileLocksMu sync.Mutex
	profileLocks   = map[string]*sync.Mutex{}
)

func lockProfile(profileID string) func() {
	profileLocksMu.Lock()
	mu, ok := profileLocks[profileID]
	if !ok {
		mu = &sync.Mutex{}
		profileLocks[profileID] = mu
	}
	profileLocksMu.Unlock()
	mu.Lock()
	return mu.Unlock
}

type StartRequest struct {
	ProfileRef         string `json:"profile_ref"`
	Headless           bool   `json:"headless,omitempty"`
	StartURL           string `json:"start_url,omitempty"`
	AllowLocal         bool   `json:"allow_local,omitempty"`
	AllowLocalUpstream bool   `json:"allow_local_upstream,omitempty"`
	KernelOverride     string `json:"kernel_override,omitempty"`
}

type StartResult struct {
	OK             bool               `json:"ok"`
	Profile        string             `json:"profile"`
	AlreadyRunning bool               `json:"already_running,omitempty"`
	ViaDaemon      bool               `json:"via_daemon,omitempty"`
	KernelKind     string             `json:"kernel_kind,omitempty"`
	KernelVersion  string             `json:"kernel_version,omitempty"`
	Runtime        store.RuntimeState `json:"runtime"`
}

// StartProfile launches (or attaches to an already-running) isolated browser + proxy forwarder.
func StartProfile(st *store.Store, req StartRequest) (*StartResult, error) {
	rec, err := st.FindProfile(req.ProfileRef)
	if err != nil {
		return nil, err
	}

	unlock := lockProfile(rec.ID)
	defer unlock()

	if rt, _ := st.LoadRuntime(rec.ID); rt != nil {
		if kernel.IsProcessAlive(rt.BrowserPID) {
			return &StartResult{
				OK:             true,
				Profile:        rec.Name,
				AlreadyRunning: true,
				Runtime:        *rt,
			}, nil
		}
		// Clean up any lingering forwarder from a crashed previous session.
		if rt.ProxyPID > 0 {
			_ = kernel.TerminateProcess(rt.ProxyPID)
		}
		_ = st.ClearRuntime(rec.ID)
	}

	// Fail-closed fingerprint integrity check before launch.
	if _, _, err := st.LoadFingerprint(rec.ID); err != nil {
		return nil, fmt.Errorf("fingerprint fail-closed check failed: %w", err)
	}

	cfg, _ := st.LoadSettings()
	kExe := cfg.KernelExe
	if req.KernelOverride != "" {
		kExe = req.KernelOverride
	}
	k := kernel.Resolve(kExe)
	if k == nil {
		return nil, errors.New("no browser kernel found; run 'browserforge kernel set <path>'")
	}

	var proxyPID, proxyPort int
	if rec.ProxyID != "" {
		pr, err := st.FindProxy(rec.ProxyID)
		if err != nil {
			return nil, fmt.Errorf("bound proxy %s missing: %w", rec.ProxyID, err)
		}
		pass, err := common.UnprotectSecret(st.DataDir, pr.PasswordEnc)
		if err != nil {
			return nil, fmt.Errorf("decrypt proxy password: %w", err)
		}
		upCfg := proxyfwd.UpstreamConfig{
			Scheme:             pr.Scheme,
			Host:               pr.Host,
			Port:               pr.Port,
			Username:           pr.Username,
			Password:           pass,
			AllowLocal:         req.AllowLocal,
			AllowLocalUpstream: req.AllowLocalUpstream,
			RuntimeFile:        st.RuntimePath(rec.ID),
		}
		proxyPID, proxyPort, err = proxyfwd.SpawnSubprocess(upCfg, filepath.Join(st.LogsDir(rec.ID), "proxy.log"))
		if err != nil {
			return nil, fmt.Errorf("start proxy forwarder: %w", err)
		}
	}

	extraArgs := append([]string(nil), cfg.ExtraArgs...)
	extraArgs = append(extraArgs, rec.ExtraArgs...)
	res, err := kernel.Launch(kernel.LaunchOptions{
		Kernel:      *k,
		ProfileID:   rec.ID,
		UserDataDir: st.UserDataDir(rec.ID),
		CacheDir:    st.CacheDir(rec.ID),
		LogFile:     filepath.Join(st.LogsDir(rec.ID), "browser.log"),
		ProxyPort:   proxyPort,
		Headless:    req.Headless,
		StartURL:    req.StartURL,
		ExtraArgs:   extraArgs,
	}, 25*time.Second)
	if err != nil {
		if proxyPID > 0 {
			_ = kernel.TerminateProcess(proxyPID)
		}
		return nil, err
	}

	rt := store.RuntimeState{
		ProfileID:  rec.ID,
		BrowserPID: res.PID,
		ProxyPID:   proxyPID,
		ProxyPort:  proxyPort,
		DebugPort:  res.DebugPort,
		WSPath:     res.WSPath,
		KernelExe:  k.ExePath,
		StartedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	if err := st.SaveRuntime(rt); err != nil {
		_ = kernel.TerminateProcess(res.PID)
		if proxyPID > 0 {
			_ = kernel.TerminateProcess(proxyPID)
		}
		return nil, err
	}
	return &StartResult{
		OK:            true,
		Profile:       rec.Name,
		KernelKind:    k.Kind,
		KernelVersion: k.Version,
		Runtime:       rt,
	}, nil
}

// StopProfile terminates browser and proxy processes for profileID and clears runtime state.
func StopProfile(st *store.Store, profileID string) error {
	unlock := lockProfile(profileID)
	defer unlock()
	rt, err := st.LoadRuntime(profileID)
	if err != nil || rt == nil {
		return nil
	}
	if rt.BrowserPID > 0 {
		_ = kernel.TerminateProcess(rt.BrowserPID)
	}
	if rt.ProxyPID > 0 {
		_ = kernel.TerminateProcess(rt.ProxyPID)
	}
	return st.ClearRuntime(profileID)
}
