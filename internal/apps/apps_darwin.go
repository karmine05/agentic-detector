//go:build darwin

package apps

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/karmine05/agentic-detector/internal/homes"
	"howett.net/plist"
)

type infoPlist struct {
	BundleName    string `plist:"CFBundleName"`
	BundleID      string `plist:"CFBundleIdentifier"`
	ShortVersion  string `plist:"CFBundleShortVersionString"`
	BundleVersion string `plist:"CFBundleVersion"`
}

func scanApps(homesList []homes.Home) []App {
	seen := map[string]bool{}
	var out []App

	scanDir := func(dir, scope string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".app") {
				continue
			}
			appPath := filepath.Join(dir, e.Name())
			info := readInfoPlist(appPath)
			k, ok := matchKnown(e.Name(), info.BundleName, info.BundleID)
			if !ok || seen[k.name] {
				continue
			}
			seen[k.name] = true
			out = append(out, App{
				Name:           k.name,
				BundleID:       info.BundleID,
				Version:        firstNonEmpty(info.ShortVersion, info.BundleVersion),
				Path:           appPath,
				PlatformSource: "applications",
				Scope:          scope,
			})
		}
	}

	scanDir("/Applications", "system")
	scanDir("/Applications/Utilities", "system")
	for _, h := range homesList {
		scanDir(filepath.Join(h.Dir, "Applications"), "user")
	}
	return out
}

func readInfoPlist(appPath string) infoPlist {
	var info infoPlist
	b, err := os.ReadFile(filepath.Join(appPath, "Contents", "Info.plist")) // #nosec G304 -- fixed path inside an enumerated .app bundle
	if err != nil {
		return info
	}
	_, _ = plist.Unmarshal(b, &info)
	return info
}
