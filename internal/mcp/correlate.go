package mcp

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/karmine05/agentic-detector/internal/proc"
)

// mcpProcessMarkers identify a process as an MCP server regardless of any
// config entry. Kept narrow (MCP-specific) to avoid mislabeling generic
// runtimes — broader AI classification lives in the classify package.
var mcpProcessMarkers = []string{
	"modelcontextprotocol",
	"@modelcontextprotocol/",
	"mcp-server",
	"mcp_server",
}

// Correlate reconciles declared servers against a process snapshot: it fills
// Running/PID/ListeningPort on stdio servers it can match to a live process,
// and appends heuristic rows (source="process") for running MCP servers that
// no config declared.
func Correlate(declared []Server, snap *proc.Snapshot) []Server {
	matched := map[int]bool{}

	for i := range declared {
		s := &declared[i]
		if s.Command == "" { // remote servers have no local process to match
			continue
		}
		base := baseCmd(s.Command)
		if base == "" {
			continue
		}
		var args []string
		if s.Args != "" {
			_ = json.Unmarshal([]byte(s.Args), &args)
		}
		for pid, p := range snap.Procs {
			if processMatches(p.Cmdline, base, args) {
				s.Running, s.PID = 1, pid
				if s.Source == "config" {
					s.Source = "both"
				}
				if port := snap.ListenPort(pid); port != 0 {
					s.ListeningPort = port
				}
				matched[pid] = true
				break
			}
		}
	}

	for pid, p := range snap.Procs {
		if matched[pid] || !isMCPProcess(p.Cmdline) {
			continue
		}
		s := Server{
			ServerName: deriveName(p.Cmdline),
			Client:     "process",
			Scope:      "global",
			Transport:  "stdio",
			Location:   "local",
			Command:    firstField(p.Cmdline),
			Source:     "process",
			Running:    1,
			PID:        pid,
			Username:   p.Username,
			Enabled:    -1,
		}
		if port := snap.ListenPort(pid); port != 0 {
			s.ListeningPort = port
		}
		declared = append(declared, s)
	}
	return declared
}

func processMatches(cmdline, base string, args []string) bool {
	low := strings.ToLower(cmdline)
	if !strings.Contains(low, strings.ToLower(base)) {
		return false
	}
	if len(args) == 0 {
		return true
	}
	// Require a distinctive arg token to also appear, so a bare "node" command
	// doesn't match every Node process.
	for _, a := range args {
		tok := strings.ToLower(lastSegment(a))
		if tok != "" && strings.Contains(low, tok) {
			return true
		}
	}
	return false
}

func isMCPProcess(cmdline string) bool {
	low := strings.ToLower(cmdline)
	for _, m := range mcpProcessMarkers {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

func baseCmd(cmd string) string {
	cmd = strings.Trim(cmd, `"'`)
	b := filepath.Base(cmd)
	return strings.TrimSuffix(strings.TrimSuffix(b, ".exe"), ".cmd")
}

func firstField(cmdline string) string {
	fields := strings.Fields(cmdline)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func lastSegment(s string) string {
	s = strings.TrimRight(s, "/\\")
	if i := strings.LastIndexAny(s, "/\\"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// deriveName picks the most server-identifying token from an MCP process
// command line (e.g. the package after @modelcontextprotocol/).
func deriveName(cmdline string) string {
	for _, f := range strings.Fields(cmdline) {
		l := strings.ToLower(f)
		if strings.Contains(l, "modelcontextprotocol") || strings.Contains(l, "mcp-server") || strings.Contains(l, "mcp_server") {
			return lastSegment(f)
		}
	}
	if f := firstField(cmdline); f != "" {
		return baseCmd(f)
	}
	return "unknown"
}
