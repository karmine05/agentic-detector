//go:build linux

package apps

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/karmine05/agentic-detector/internal/homes"
)

func scanApps(homesList []homes.Home) []App {
	seen := map[string]bool{}
	var out []App

	scanDir := func(dir, scope string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".desktop") {
				continue
			}
			name, exec := parseDesktop(filepath.Join(dir, e.Name()))
			ka, ok := matchKnown(e.Name(), name, exec)
			if !ok || seen[ka.name] {
				continue
			}
			seen[ka.name] = true
			out = append(out, App{
				Name:           ka.name,
				Path:           firstNonEmpty(exec, e.Name()),
				PlatformSource: "desktop-file",
				Scope:          scope,
			})
		}
	}

	scanDir("/usr/share/applications", "system")
	scanDir("/usr/local/share/applications", "system")
	for _, h := range homesList {
		scanDir(filepath.Join(h.Dir, ".local", "share", "applications"), "user")
	}

	// Ollama commonly installs as a service binary with no .desktop entry.
	for _, b := range []string{"/usr/local/bin/ollama", "/usr/bin/ollama"} {
		if fi, err := os.Stat(b); err == nil && !fi.IsDir() && !seen["ollama"] {
			seen["ollama"] = true
			out = append(out, App{Name: "ollama", Path: b, PlatformSource: "desktop-file", Scope: "system"})
		}
	}
	return out
}

func parseDesktop(path string) (name, exec string) {
	b, err := os.ReadFile(path) // #nosec G304 -- fixed-extension file under an enumerated applications dir
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case name == "" && strings.HasPrefix(line, "Name="):
			name = strings.TrimPrefix(line, "Name=")
		case exec == "" && strings.HasPrefix(line, "Exec="):
			exec = strings.TrimPrefix(line, "Exec=")
		}
	}
	return name, exec
}
