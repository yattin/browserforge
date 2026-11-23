package fingerprint

import (
	"strings"
	"testing"
)

func TestCanonicalJSONNoHTMLEscaping(t *testing.T) {
	input := map[string]any{
		"b":    "a<b>c&d",
		"a":    1920.0,
		"zero": -0.0,
		"nested": map[string]any{
			"z": true,
			"m": []any{1.0, "x\"y\\z"},
		},
	}
	got, err := CanonicalJSON(input)
	if err != nil {
		t.Fatalf("CanonicalJSON error: %v", err)
	}
	want := `{"a":1920,"b":"a<b>c&d","nested":{"m":[1,"x\"y\\z"],"z":true},"zero":0}`
	if got != want {
		t.Fatalf("CanonicalJSON mismatch:\n got: %s\nwant: %s", got, want)
	}
	if strings.Contains(got, `\u003c`) || strings.Contains(got, `\u0026`) {
		t.Fatalf("CanonicalJSON must not HTML-escape <, >, &")
	}
}

func TestGenerateAndValidateBerylV1(t *testing.T) {
	host := HostProfile{
		OS:              "win11",
		PlatformVersion: "15.0.0",
		Cores:           16,
		MemoryGB:        32,
		ScreenWidth:     2560,
		ScreenHeight:    1440,
		GPUVendor:       "nvidia",
	}
	fp, err := Generate(GenerateParams{
		ProfileID:      "11111111-2222-4333-8444-555555555555",
		Template:       "win11_x64_nvidia",
		BrowserVersion: "156.0.8078.79",
		Brand:          "Google Chrome",
		Timezone:       "America/New_York",
		Languages:      []string{"en-US", "en"},
		Host:           host,
		Seed:           strings.Repeat("ab", 32),
		Now:            "2026-01-01T00:00:00.000Z",
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if fp.Algorithm != "beryl-v1" {
		t.Fatalf("expected algorithm beryl-v1, got %q", fp.Algorithm)
	}
	raw, err := fp.MarshalIndented()
	if err != nil {
		t.Fatalf("MarshalIndented: %v", err)
	}
	parsed, err := ValidateIntegrity(raw, fp.ProfileID)
	if err != nil {
		t.Fatalf("ValidateIntegrity failed: %v", err)
	}
	if parsed.Checksum != fp.Checksum {
		t.Fatalf("checksum mismatch")
	}

	// Tamper test must fail closed.
	tampered := strings.Replace(string(raw), `"America/New_York"`, `"Asia/Tokyo"`, 1)
	if _, err := ValidateIntegrity([]byte(tampered), fp.ProfileID); err == nil {
		t.Fatalf("expected tampered fingerprint to fail validation")
	}

	// WithEditable preserves seed and updates checksum.
	edited, err := fp.WithEditable("Europe/London", []string{"en-GB", "en"}, nil)
	if err != nil {
		t.Fatalf("WithEditable failed: %v", err)
	}
	if edited.Seed != fp.Seed {
		t.Fatalf("seed should remain constant on WithEditable")
	}
	if edited.Checksum == fp.Checksum {
		t.Fatalf("checksum should change when timezone/languages change")
	}
	editedRaw, _ := edited.MarshalIndented()
	if _, err := ValidateIntegrity(editedRaw, fp.ProfileID); err != nil {
		t.Fatalf("edited fingerprint failed validation: %v", err)
	}

	// Consistency check.
	rep := ValidateConsistency(edited, ValidationContext{
		Host:          host,
		KernelVersion: "156.0.8078.79",
		HasProxy:      true,
		ProxyTimezone: "Europe/London",
		FileReadOnly:  true,
		ExpectedID:    fp.ProfileID,
	})
	if !rep.OK {
		t.Fatalf("expected consistency report OK, got %+v", rep)
	}
}
