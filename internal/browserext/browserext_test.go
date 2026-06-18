package browserext

import "testing"

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
