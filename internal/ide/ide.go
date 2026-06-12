// Package ide enumerates installed editor/IDE plugins across all major editor
// families by reading their on-disk install locations and manifests. It is
// fully self-contained (no dependency on osquery's built-in vscode_extensions
// table) and adds an AI-classification layer via the classify package.
package ide

import (
	"github.com/karmine05/agentic-detector/internal/classify"
	"github.com/karmine05/agentic-detector/internal/homes"
	"github.com/karmine05/agentic-detector/internal/paths"
)

// Plugin is one installed editor extension/plugin.
type Plugin struct {
	UID, Username, HomeDir string
	Editor                 string // vscode, cursor, intellij-idea, zed, sublime, neovim, emacs, ...
	EditorFamily           string // vscode | jetbrains | zed | sublime | vim | emacs
	PluginID               string
	Name                   string
	Version                string
	Publisher              string
	InstallPath            string
	ManifestPath           string
	IsAI                   int
	AICategory             string
}

// Scan returns every plugin discovered under the given home directory.
func Scan(h homes.Home) []Plugin {
	r := paths.For(h.Dir)
	var out []Plugin
	out = append(out, scanVSCodeFamily(h, r)...)
	out = append(out, scanJetBrains(h, r)...)
	out = append(out, scanZed(h, r)...)
	out = append(out, scanSublime(h, r)...)
	out = append(out, scanVim(h)...)
	out = append(out, scanEmacs(h)...)
	return out
}

// finish stamps ownership and classification onto a plugin row.
func (p Plugin) finish(h homes.Home, isAI bool, cat string) Plugin {
	p.UID, p.Username, p.HomeDir = h.UID, h.Username, h.Dir
	if isAI {
		p.IsAI = 1
		p.AICategory = cat
	}
	return p
}

// classifyByName is the fallback classifier for editors without a curated id
// map (Zed, Sublime, Vim, Emacs).
func classifyByName(s string) (bool, string) { return classify.ByName(s) }
