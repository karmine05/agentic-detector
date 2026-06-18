package browserext

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karmine05/agentic-detector/internal/homes"
)

func TestHasBroadHostPerms(t *testing.T) {
	yes := [][]string{
		{"<all_urls>"},
		{"tabs", "*://*/*"},
		{"https://*/*"},
		{"http://*/*"},
		{" <all_urls> "},
	}
	for _, p := range yes {
		if !hasBroadHostPerms(p) {
			t.Errorf("hasBroadHostPerms(%v) = false, want true", p)
		}
	}
	no := [][]string{
		{"tabs", "storage"},
		{"https://mail.google.com/*"},
		nil,
	}
	for _, p := range no {
		if hasBroadHostPerms(p) {
			t.Errorf("hasBroadHostPerms(%v) = true, want false", p)
		}
	}
}

func TestChromiumSideloaded(t *testing.T) {
	// fromWebstore: -1 unknown, 0 no, 1 yes. location: 0 unknown, 1 internal, 4 unpacked, 5 component, 10 external.
	cases := []struct {
		fw, loc int
		want    bool
	}{
		{1, 1, false},  // store + internal
		{0, 1, true},   // explicitly not webstore
		{-1, 4, true},  // unpacked
		{-1, 10, true}, // external/policy
		{-1, 5, false}, // component
		{-1, 0, false}, // both unknown -> conservative, no flag
		{1, 4, true},   // store-flagged but unpacked location -> still anomalous
		{1, 10, true},  // store-flagged but external/policy location -> still anomalous
	}
	for _, c := range cases {
		if got := chromiumSideloaded(c.fw, c.loc); got != c.want {
			t.Errorf("chromiumSideloaded(%d,%d)=%v want %v", c.fw, c.loc, got, c.want)
		}
	}
}

func TestGeckoSideloaded(t *testing.T) {
	cases := []struct {
		signed  int
		foreign bool
		want    bool
	}{
		{2, false, false},                  // privileged
		{1, false, false},                  // signed
		{0, false, true},                   // missing signature
		{-1, false, true},                  // unknown-signature state
		{1, true, true},                    // signed but foreign-installed
		{signedStateUnknown, false, false}, // truly unknown -> conservative
	}
	for _, c := range cases {
		if got := geckoSideloaded(c.signed, c.foreign); got != c.want {
			t.Errorf("geckoSideloaded(%d,%v)=%v want %v", c.signed, c.foreign, got, c.want)
		}
	}
}

func TestComputeRisk(t *testing.T) {
	e := Extension{HostPerms: []string{"<all_urls>"}, Sideloaded: true}
	e.computeRisk()
	if e.RiskFlags != "broad_host_permissions,sideloaded_unverified" {
		t.Errorf("RiskFlags=%q want both flags in order", e.RiskFlags)
	}
	clean := Extension{HostPerms: []string{"tabs"}, Sideloaded: false}
	clean.computeRisk()
	if clean.RiskFlags != "" {
		t.Errorf("RiskFlags=%q want empty", clean.RiskFlags)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCollectChromiumProfile(t *testing.T) {
	profile := t.TempDir()
	exts := filepath.Join(profile, "Extensions")

	// AI extension on disk: i18n name, broad host perms.
	aiID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	writeFile(t, filepath.Join(exts, aiID, "1.0.0", "manifest.json"),
		`{"name":"__MSG_extName__","version":"1.0.0","default_locale":"en","manifest_version":3,"host_permissions":["<all_urls>"]}`)
	writeFile(t, filepath.Join(exts, aiID, "1.0.0", "_locales", "en", "messages.json"),
		`{"extName":{"message":"ChatGPT Sidebar"}}`)

	// Non-AI extension on disk -> must be dropped.
	nonAI := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	writeFile(t, filepath.Join(exts, nonAI, "2.0.0", "manifest.json"),
		`{"name":"Prettier","version":"2.0.0","manifest_version":3}`)

	// Unpacked AI extension: NOT under Extensions/, only in Preferences (location 4).
	unpackedSrc := t.TempDir()
	writeFile(t, filepath.Join(unpackedSrc, "manifest.json"),
		`{"name":"Claude Dev","version":"9.9.9","manifest_version":3,"permissions":["<all_urls>"]}`)
	unpackedID := "cccccccccccccccccccccccccccccccc"

	// Secure Preferences: AI ext not-from-webstore (sideloaded), unpacked entry.
	prefs := map[string]any{
		"extensions": map[string]any{
			"settings": map[string]any{
				aiID:       map[string]any{"from_webstore": false, "location": 1},
				unpackedID: map[string]any{"location": 4, "path": unpackedSrc, "manifest": map[string]any{"name": "Claude Dev", "version": "9.9.9", "permissions": []string{"<all_urls>"}}},
			},
		},
	}
	pb, _ := json.Marshal(prefs)
	writeFile(t, filepath.Join(profile, "Secure Preferences"), string(pb))

	got := collectChromiumProfile(profile, "chrome", "Default", homes.Home{UID: "501", Username: "tester"})

	by := map[string]Extension{}
	for _, e := range got {
		by[e.ID] = e
	}
	if _, ok := by[nonAI]; ok {
		t.Error("non-AI Prettier should be dropped (AI-only table)")
	}
	ai, ok := by[aiID]
	if !ok {
		t.Fatalf("AI extension not found; got %d (%+v)", len(got), got)
	}
	if ai.Name != "ChatGPT Sidebar" {
		t.Errorf("name=%q want resolved i18n 'ChatGPT Sidebar'", ai.Name)
	}
	if ai.Engine != "chromium" || ai.Browser != "chrome" || ai.Profile != "Default" {
		t.Errorf("metadata wrong: %+v", ai)
	}
	if ai.SHA256 == "" {
		t.Error("AI extension manifest hash empty")
	}
	for _, want := range []string{"broad_host_permissions", "sideloaded_unverified"} {
		if !contains(ai.RiskFlags, want) {
			t.Errorf("RiskFlags=%q missing %q", ai.RiskFlags, want)
		}
	}
	up, ok := by[unpackedID]
	if !ok {
		t.Fatal("unpacked extension (Preferences-only) not recovered")
	}
	if up.Name != "Claude Dev" || up.SHA256 == "" || !contains(up.RiskFlags, "sideloaded_unverified") {
		t.Errorf("unpacked ext wrong: %+v", up)
	}
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }
