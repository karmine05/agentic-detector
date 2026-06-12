// Package tables exposes a single, unified osquery table — agentic_software —
// covering every agentic-software kind (MCP servers, IDE plugins, AI agent
// CLIs, AI desktop apps, live AI/MCP sockets) through one schema with a `kind`
// discriminator and a JSON `detail` column for kind-specific fields.
//
// It is optimized for a lightweight footprint:
//   - constraint pushdown: a query with `WHERE kind = '...'` (or `kind IN (...)`)
//     only runs the collectors it needs;
//   - one process/connection snapshot per query (shared across mcp/agents/apps/
//     sockets), skipped entirely when only ide_plugin is requested;
//   - one home-directory enumeration and one MCP-config scan, shared between the
//     mcp_server and socket collectors.
package tables

import (
	"context"
	"encoding/json"
	"net"
	"net/url"
	"sort"
	"strconv"

	"github.com/osquery/osquery-go/plugin/table"

	"github.com/karmine05/agentic-detector/internal/agents"
	"github.com/karmine05/agentic-detector/internal/apps"
	"github.com/karmine05/agentic-detector/internal/homes"
	"github.com/karmine05/agentic-detector/internal/ide"
	"github.com/karmine05/agentic-detector/internal/mcp"
	"github.com/karmine05/agentic-detector/internal/netsock"
	"github.com/karmine05/agentic-detector/internal/proc"
)

// allKinds is the set of values the `kind` column can take.
var allKinds = []string{"mcp_server", "ide_plugin", "ai_agent", "ai_app", "socket"}

// columns is the unified schema. Common fields are first-class; everything
// kind-specific lives in `detail` (compact JSON, empty fields omitted).
var columns = []string{
	"kind",       // mcp_server | ide_plugin | ai_agent | ai_app | socket
	"name",       // server/plugin/agent/app/process display name
	"identifier", // plugin_id | bundle_id | mcp server name | agent binary | socket service
	"category",   // classification bucket (coding-assistant, agent-runtime, ai-api-egress, ...)
	"is_ai",      // 0/1
	"location",   // local | remote
	"source",     // provenance: client | editor | install_method | platform_source | direction
	"version",
	"path",     // config/install/binary/app/process path
	"endpoint", // remote MCP url or socket remote addr:port
	"running",  // 0/1
	"pid",
	"port", // listening_port | api_port | local_port
	"uid",
	"username",
	"detail", // JSON: kind-specific extras
}

// All returns the single table plugin exposed by the extension.
func All() []*table.Plugin {
	return []*table.Plugin{
		table.NewPlugin("agentic_software", columnDefs(), generate),
	}
}

func columnDefs() []table.ColumnDefinition {
	defs := make([]table.ColumnDefinition, 0, len(columns))
	for _, c := range columns {
		switch c {
		case "is_ai", "running", "pid", "port":
			defs = append(defs, table.IntegerColumn(c))
		default:
			defs = append(defs, table.TextColumn(c))
		}
	}
	return defs
}

func generate(ctx context.Context, qc table.QueryContext) ([]map[string]string, error) {
	kinds := requestedKinds(qc)

	hs := homes.All()

	needProc := kinds["mcp_server"] || kinds["ai_agent"] || kinds["ai_app"] || kinds["socket"]
	var snap *proc.Snapshot
	if needProc {
		snap = proc.Take(ctx) // single snapshot, shared below
	}

	// MCP config scan is shared by the mcp_server rows and the socket egress
	// host set, so do it at most once.
	var servers []mcp.Server
	if kinds["mcp_server"] || kinds["socket"] {
		for _, h := range hs {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			servers = append(servers, mcp.ScanConfigs(h)...)
		}
	}

	rows := make([]map[string]string, 0, 128)

	if kinds["socket"] {
		for _, s := range netsock.Collect(snap, remoteHosts(servers)) {
			rows = append(rows, socketRow(s))
		}
	}
	if kinds["mcp_server"] {
		for _, s := range mcp.Correlate(servers, snap) {
			rows = append(rows, mcpRow(s))
		}
	}
	if kinds["ide_plugin"] {
		for _, h := range hs {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			for _, p := range ide.Scan(h) {
				rows = append(rows, ideRow(p))
			}
		}
	}
	if kinds["ai_agent"] {
		for _, h := range hs {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			for _, a := range agents.Scan(h, snap) {
				rows = append(rows, agentRow(a))
			}
		}
	}
	if kinds["ai_app"] {
		for _, a := range apps.Scan(hs, snap) {
			rows = append(rows, appRow(a))
		}
	}
	return rows, nil
}

// requestedKinds reads `kind` equality/IN constraints so we only run the
// collectors the query asks for. Any non-equality predicate (!=, LIKE) falls
// back to all kinds (safe superset).
func requestedKinds(qc table.QueryContext) map[string]bool {
	cl, ok := qc.Constraints["kind"]
	if !ok {
		return allSet()
	}
	want := map[string]bool{}
	for _, c := range cl.Constraints {
		if c.Operator == table.OperatorEquals {
			want[c.Expression] = true
		}
	}
	if len(want) == 0 {
		return allSet()
	}
	// Keep only valid kinds; if the filter excluded everything valid, the query
	// legitimately wants nothing.
	out := map[string]bool{}
	for _, k := range allKinds {
		if want[k] {
			out[k] = true
		}
	}
	return out
}

func allSet() map[string]bool {
	m := make(map[string]bool, len(allKinds))
	for _, k := range allKinds {
		m[k] = true
	}
	return m
}

// ---- row mappers ----

func mcpRow(s mcp.Server) map[string]string {
	return row(map[string]string{
		"kind":       "mcp_server",
		"name":       s.ServerName,
		"identifier": s.ServerName,
		"category":   "mcp-server",
		"is_ai":      "1",
		"location":   s.Location,
		"source":     s.Client,
		"path":       s.ConfigPath,
		"endpoint":   s.URL,
		"running":    itoa(s.Running),
		"pid":        itoa(s.PID),
		"port":       itoa(s.ListeningPort),
		"uid":        s.UID,
		"username":   s.Username,
	}, map[string]string{
		"transport":   s.Transport,
		"command":     s.Command,
		"args":        s.Args,
		"env_keys":    s.EnvKeys,
		"scope":       s.Scope,
		"source_kind": s.Source,
		"enabled":     itoa(s.Enabled),
	})
}

func ideRow(p ide.Plugin) map[string]string {
	return row(map[string]string{
		"kind":       "ide_plugin",
		"name":       p.Name,
		"identifier": p.PluginID,
		"category":   p.AICategory,
		"is_ai":      itoa(p.IsAI),
		"location":   "local",
		"source":     p.Editor,
		"version":    p.Version,
		"path":       p.InstallPath,
		"uid":        p.UID,
		"username":   p.Username,
	}, map[string]string{
		"editor_family": p.EditorFamily,
		"publisher":     p.Publisher,
		"manifest_path": p.ManifestPath,
	})
}

func agentRow(a agents.Agent) map[string]string {
	return row(map[string]string{
		"kind":       "ai_agent",
		"name":       a.Name,
		"identifier": a.Binary,
		"is_ai":      itoa(a.IsAI),
		"location":   "local",
		"source":     a.InstallMethod,
		"version":    a.Version,
		"path":       a.Path,
		"running":    itoa(a.Running),
		"pid":        itoa(a.PID),
		"uid":        a.UID,
		"username":   a.Username,
	}, map[string]string{
		"runtime": a.Runtime,
		"binary":  a.Binary,
	})
}

func appRow(a apps.App) map[string]string {
	return row(map[string]string{
		"kind":       "ai_app",
		"name":       a.Name,
		"identifier": a.BundleID,
		"is_ai":      "1",
		"location":   "local",
		"source":     a.PlatformSource,
		"version":    a.Version,
		"path":       a.Path,
		"running":    itoa(a.Running),
		"pid":        itoa(a.PID),
		"port":       itoa(a.APIPort),
	}, map[string]string{
		"vendor":           a.Vendor,
		"bundle_id":        a.BundleID,
		"scope":            a.Scope,
		"serves_local_api": itoa(a.ServesLocalAPI),
	})
}

func socketRow(s netsock.Socket) map[string]string {
	loc := "local"
	endpoint := ""
	if s.Direction == "established" {
		loc = "remote"
		if s.RemoteAddress != "" {
			endpoint = net.JoinHostPort(s.RemoteAddress, strconv.Itoa(s.RemotePort))
		}
	}
	return row(map[string]string{
		"kind":       "socket",
		"name":       s.ProcessName,
		"identifier": s.Service,
		"category":   s.Category,
		"is_ai":      itoa(s.IsAI),
		"location":   loc,
		"source":     s.Direction,
		"path":       s.ProcessPath,
		"endpoint":   endpoint,
		"running":    "1",
		"pid":        itoa(s.PID),
		"port":       itoa(s.LocalPort),
		"username":   s.Username,
	}, map[string]string{
		"protocol":      s.Protocol,
		"local_address": s.LocalAddress,
		"remote_host":   s.RemoteHost,
		"service":       s.Service,
		"cmdline":       s.Cmdline,
	})
}

// ---- helpers ----

// row fills a complete column map from a set of populated fields plus a
// detail map (empty detail entries are dropped before JSON-encoding).
func row(fields, detail map[string]string) map[string]string {
	m := make(map[string]string, len(columns))
	for _, c := range columns {
		m[c] = ""
	}
	for k, v := range fields {
		m[k] = v
	}
	m["detail"] = compactJSON(detail)
	return m
}

func compactJSON(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k, v := range m {
		if v != "" && v != "0" {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		out[k] = m[k]
	}
	b, err := json.Marshal(out)
	if err != nil {
		return ""
	}
	return string(b)
}

func remoteHosts(servers []mcp.Server) map[string]string {
	out := map[string]string{}
	for _, s := range servers {
		if s.Location == "remote" && s.URL != "" {
			if u, err := url.Parse(s.URL); err == nil && u.Hostname() != "" {
				out[u.Hostname()] = s.ServerName
			}
		}
	}
	return out
}

func itoa(i int) string { return strconv.Itoa(i) }
