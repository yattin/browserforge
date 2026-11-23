package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"browserforge/internal/common"
	"browserforge/internal/fingerprint"
)

type Settings struct {
	KernelExe string   `json:"kernel_exe,omitempty"`
	Timezone  string   `json:"timezone,omitempty"`
	Languages []string `json:"languages,omitempty"`
	ExtraArgs []string `json:"extra_args,omitempty"`
}

type ProxyRecord struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Scheme        string `json:"scheme"` // http, https, socks5
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Username      string `json:"username,omitempty"`
	PasswordEnc   string `json:"password_enc,omitempty"`
	ExitIP        string `json:"exit_ip,omitempty"`
	ExitCountry   string `json:"exit_country,omitempty"`
	ExitTimezone  string `json:"exit_timezone,omitempty"`
	LastCheckedAt string `json:"last_checked_at,omitempty"`
	CreatedAt     string `json:"created_at"`
}

// PublicProxy is a redacted view safe for CLI / JSON display.
type PublicProxy struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Scheme        string `json:"scheme"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Username      string `json:"username,omitempty"`
	HasPassword   bool   `json:"has_password"`
	ExitIP        string `json:"exit_ip,omitempty"`
	ExitCountry   string `json:"exit_country,omitempty"`
	ExitTimezone  string `json:"exit_timezone,omitempty"`
	LastCheckedAt string `json:"last_checked_at,omitempty"`
	CreatedAt     string `json:"created_at"`
}

func (p ProxyRecord) Public() PublicProxy {
	return PublicProxy{
		ID:            p.ID,
		Name:          p.Name,
		Scheme:        p.Scheme,
		Host:          p.Host,
		Port:          p.Port,
		Username:      p.Username,
		HasPassword:   p.PasswordEnc != "",
		ExitIP:        p.ExitIP,
		ExitCountry:   p.ExitCountry,
		ExitTimezone:  p.ExitTimezone,
		LastCheckedAt: p.LastCheckedAt,
		CreatedAt:     p.CreatedAt,
	}
}

type ProfileRecord struct {
	ID          string                         `json:"id"`
	Name        string                         `json:"name"`
	Group       string                         `json:"group,omitempty"`
	Notes       string                         `json:"notes,omitempty"`
	Template    string                         `json:"template"`
	ProxyID     string                         `json:"proxy_id,omitempty"`
	Timezone    string                         `json:"timezone"`
	Languages   []string                       `json:"languages"`
	Geolocation *fingerprint.GeolocationSetting `json:"geolocation,omitempty"`
	ExtraArgs   []string                       `json:"extra_args,omitempty"`
	CreatedAt   string                         `json:"created_at"`
	UpdatedAt   string                         `json:"updated_at"`
}

type RuntimeState struct {
	ProfileID   string  `json:"profile_id"`
	BrowserPID  int     `json:"browser_pid"`
	ProxyPID    int     `json:"proxy_pid,omitempty"`
	ProxyPort   int     `json:"proxy_port,omitempty"`
	DebugPort   int     `json:"debug_port"`
	WSPath      string  `json:"ws_path,omitempty"`
	KernelExe   string  `json:"kernel_exe"`
	StartedAt   string  `json:"started_at"`
	LastMouseX  float64 `json:"last_mouse_x,omitempty"`
	LastMouseY  float64 `json:"last_mouse_y,omitempty"`
	HasMousePos bool    `json:"has_mouse_pos,omitempty"`
}

type Store struct {
	DataDir string
}

func Open(dataDir string) (*Store, error) {
	if strings.TrimSpace(dataDir) == "" {
		dataDir = common.DefaultDataDir()
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, err
	}
	if err := common.EnsurePrivateDir(abs); err != nil {
		return nil, err
	}
	if err := common.EnsurePrivateDir(filepath.Join(abs, "profiles")); err != nil {
		return nil, err
	}
	return &Store{DataDir: abs}, nil
}

func (s *Store) settingsPath() string { return filepath.Join(s.DataDir, "settings.json") }
func (s *Store) proxiesPath() string  { return filepath.Join(s.DataDir, "proxies.json") }
func (s *Store) profilesPath() string { return filepath.Join(s.DataDir, "profiles.json") }

func (s *Store) ProfileDir(id string) string {
	return filepath.Join(s.DataDir, "profiles", id)
}

func (s *Store) UserDataDir(id string) string {
	return filepath.Join(s.ProfileDir(id), "userdata")
}

func (s *Store) CacheDir(id string) string {
	return filepath.Join(s.ProfileDir(id), "cache")
}

func (s *Store) LogsDir(id string) string {
	return filepath.Join(s.ProfileDir(id), "logs")
}

func (s *Store) FingerprintPath(id string) string {
	return filepath.Join(s.UserDataDir(id), "beryl", "fingerprint.json")
}

func (s *Store) RuntimePath(id string) string {
	return filepath.Join(s.ProfileDir(id), "runtime.json")
}

func (s *Store) ManifestPath(id string) string {
	return filepath.Join(s.ProfileDir(id), "manifest.json")
}

func readJSONFile[T any](path string, fallback T) (T, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fallback, nil
		}
		return fallback, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return fallback, nil
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		return fallback, fmt.Errorf("parse %s: %w", path, err)
	}
	return out, nil
}

func writeJSONFile(path string, v any, perm os.FileMode) error {
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	return common.WriteFileAtomic(path, []byte(sb.String()), perm)
}

func (s *Store) LoadSettings() (Settings, error) {
	return readJSONFile(s.settingsPath(), Settings{
		Timezone:  "America/New_York",
		Languages: []string{"en-US", "en"},
	})
}

func (s *Store) SaveSettings(cfg Settings) error {
	return writeJSONFile(s.settingsPath(), cfg, 0o600)
}

func (s *Store) ListProxies() ([]ProxyRecord, error) {
	return readJSONFile(s.proxiesPath(), []ProxyRecord{})
}

func (s *Store) SaveProxies(list []ProxyRecord) error {
	return writeJSONFile(s.proxiesPath(), list, 0o600)
}

func (s *Store) FindProxy(idOrName string) (*ProxyRecord, error) {
	list, err := s.ListProxies()
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].ID == idOrName || strings.EqualFold(list[i].Name, idOrName) {
			return &list[i], nil
		}
	}
	return nil, fmt.Errorf("proxy %q not found", idOrName)
}

func (s *Store) ListProfiles() ([]ProfileRecord, error) {
	return readJSONFile(s.profilesPath(), []ProfileRecord{})
}

func (s *Store) SaveProfiles(list []ProfileRecord) error {
	return writeJSONFile(s.profilesPath(), list, 0o600)
}

func (s *Store) FindProfile(idOrName string) (*ProfileRecord, error) {
	list, err := s.ListProfiles()
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].ID == idOrName || strings.EqualFold(list[i].Name, idOrName) {
			return &list[i], nil
		}
	}
	return nil, fmt.Errorf("profile %q not found", idOrName)
}

func (s *Store) InitProfileLayout(p ProfileRecord, fp *fingerprint.FingerprintData) error {
	dirs := []string{
		s.ProfileDir(p.ID),
		filepath.Join(s.UserDataDir(p.ID), "beryl"),
		s.CacheDir(p.ID),
		s.LogsDir(p.ID),
	}
	for _, d := range dirs {
		if err := common.EnsurePrivateDir(d); err != nil {
			return err
		}
	}
	if err := s.WriteFingerprint(p.ID, fp); err != nil {
		return err
	}
	manifest := map[string]any{
		"profile_id": p.ID,
		"name":       p.Name,
		"template":   p.Template,
		"created_at": p.CreatedAt,
		"updated_at": time.Now().UTC().Format(time.RFC3339),
	}
	return writeJSONFile(s.ManifestPath(p.ID), manifest, 0o600)
}

func (s *Store) WriteFingerprint(profileID string, fp *fingerprint.FingerprintData) error {
	raw, err := fp.MarshalIndented()
	if err != nil {
		return err
	}
	return common.WriteFileAtomic(s.FingerprintPath(profileID), raw, 0o444)
}

func (s *Store) LoadFingerprint(profileID string) (*fingerprint.FingerprintData, bool, error) {
	path := s.FingerprintPath(profileID)
	info, err := os.Stat(path)
	if err != nil {
		return nil, false, err
	}
	isRO := info.Mode().Perm()&0o222 == 0
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, isRO, err
	}
	fp, err := fingerprint.ValidateIntegrity(raw, profileID)
	if err != nil {
		return nil, isRO, err
	}
	return fp, isRO, nil
}

func (s *Store) LoadRuntime(profileID string) (*RuntimeState, error) {
	raw, err := os.ReadFile(s.RuntimePath(profileID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var st RuntimeState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (s *Store) SaveRuntime(st RuntimeState) error {
	return writeJSONFile(s.RuntimePath(st.ProfileID), st, 0o600)
}

func (s *Store) ClearRuntime(profileID string) error {
	err := os.Remove(s.RuntimePath(profileID))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *Store) DeleteProfileDir(profileID string) error {
	fpPath := s.FingerprintPath(profileID)
	_ = common.SetReadOnly(fpPath, false)
	return os.RemoveAll(s.ProfileDir(profileID))
}
