// Package browserext discovers AI browser extensions across Chromium- and
// Gecko-family browsers, for every user home on the host. It is disk-only (no
// process snapshot) and read-only: extension manifests/registries are parsed
// and the on-disk artifact is hashed, never executed. Install provenance is
// read from local browser state (Chromium Preferences / Gecko extensions.json),
// never by contacting a web store. Only AI-classified extensions are emitted.
package browserext

import (
	"os"
)

// signedStateUnknown marks a Gecko addon whose signedState we could not read.
const signedStateUnknown = -99

// Extension is one discovered AI browser extension (a browser_extension row).
type Extension struct {
	UID, Username string
	Browser       string // chrome, edge, brave, arc, opera, vivaldi, chromium, comet, dia, firefox, zen, ...
	Engine        string // chromium | gecko
	Profile       string // Default, Profile 1, <gecko profile name>
	ID            string
	Name          string
	Version       string
	Path          string // manifest.json (chromium) or .xpi (gecko) — the hashed artifact
	Category      string
	Scope         string // user
	ManifestVer   int    // chromium manifest_version (0 = unknown)
	HostPerms     []string
	FromWebstore  int  // -1 unknown, 0 no, 1 yes (chromium)
	SignedState   int  // signedStateUnknown, or Gecko signedState (-2..2)
	Sideloaded    bool // set per-engine; feeds computeRisk
	SHA256        string
	RiskFlags     string
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
