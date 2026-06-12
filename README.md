# agentic-detector

A cross-platform **osquery extension** (Go) that gives Fleet visibility into the
*agentic software layer* that traditional EDR/MDM and osquery's built-in tables
miss: **MCP servers, AI agent CLIs, AI desktop apps, IDE plugins, and live
AI/MCP network sockets**.

It is **detection-only** — read-only tables, no remediation, and it never
executes a discovered binary.

## The `agentic_software` table

One table covers everything. A `kind` column discriminates the row type; common
fields are first-class columns; kind-specific extras live in a compact JSON
`detail` column. The extension emits one row per user **per host** —
enumerating all home directories (`/Users/*`, `/home/*`+`/root`, `C:\Users\*`),
not just the daemon account's.

| `kind` | Row represents |
|---|---|
| `mcp_server` | An MCP server declared in any client config (Claude Desktop/Code, Cursor, Windsurf, VS Code, Zed, Cline, Roo, Continue) and/or a running MCP server process. |
| `ide_plugin` | An installed editor plugin (VS Code family incl. Cursor/Windsurf/VSCodium/Trae/Antigravity/code-server, JetBrains, Zed, Sublime, Neovim/Vim, Emacs). |
| `ai_agent` | An installed AI agent CLI (Claude Code, Gemini, Codex, aider, goose, opencode, Cline, Continue, cursor-agent, Amazon Q/Kiro). |
| `ai_app` | An installed AI desktop app (Claude Desktop, ChatGPT, Ollama, LM Studio, Jan, GPT4All, Msty, AnythingLLM, Perplexity, Cursor, Windsurf, Antigravity). |
| `socket` | A live AI/MCP network socket — local inference/MCP listener or outbound AI/MCP egress. |

### Columns

`kind, name, identifier, category, is_ai, location, source, version, path, endpoint, running, pid, port, uid, username, detail`

| Column | Meaning (varies by kind) |
|---|---|
| `name` | server / plugin / agent / app / process name |
| `identifier` | mcp server name · `publisher.name` · agent binary · bundle id · socket service |
| `category` | classification bucket (`coding-assistant`, `agent-runtime`, `inference-api-local`, `mcp-remote-egress`, `ai-api-egress`, `mcp-server`, …) |
| `is_ai` | 0/1 |
| `location` | `local` or `remote` |
| `source` | provenance: MCP client · editor · install method · platform source · socket direction |
| `path` | config / install / binary / app / process path |
| `endpoint` | remote MCP url, or socket remote `addr:port` |
| `running`,`pid`,`port` | liveness; `port` = listening / api / local port |
| `detail` | JSON of kind-specific extras (`transport`, `args`, `env_keys` (names only), `publisher`, `editor_family`, `runtime`, `protocol`, `remote_host`, `cmdline`, …) |

**Lightweight by design:** a query with `WHERE kind = '…'` (or `kind IN (…)`)
only runs the collectors it needs (constraint pushdown); the process/connection
snapshot, home enumeration and config scan happen at most **once** per query and
are shared across collectors; `kind = 'ide_plugin'` skips the process snapshot
entirely.

## How detection works

- **Config parsing** — JSON/YAML across every known MCP client; `command`⇒local, `url`/`serverUrl`⇒remote; VS Code's `servers` key vs everyone else's `mcpServers`; Zed's nested `command` object; per-project `.mcp.json`/`.cursor`/`.vscode`/`.roo` via a bounded walk of common dev roots.
- **Process/connection snapshot** — one `gopsutil` snapshot per query feeds liveness (`running`/`pid`), listening-port fill, and the `agentic_sockets` table.
- **Classification KB** — `internal/classify/kb.json` (embedded) maps known extension ids, process-cmdline markers, inference ports, and hosted-AI API hostnames to categories. Egress is attributed **process-first** (an AI/agent process's connections are AI traffic) before any DNS heuristic; no brittle IP allowlists.

## Build

```bash
make check       # gofmt + go vet + go test -race
make build-all   # all platform binaries into ./build/ (Fleet-named)
```

Outputs (named exactly as Fleet expects):

```
build/agentic_detector_macos.ext             # universal (amd64 + arm64)
build/agentic_detector_linux.ext             # amd64
build/agentic_detector_linux_arm64.ext
build/agentic_detector_windows.ext.exe       # amd64
build/agentic_detector_windows_arm64.ext.exe
```

Sign before distribution (osquery refuses world-writable / non-root-owned
extensions unless `--allow_unsafe`):

- macOS: `codesign -s "Developer ID Application: <ORG>" --options runtime build/agentic_detector_macos.ext` then `notarytool` + `stapler`.
- Windows: `signtool sign /fd SHA256 /a build/agentic_detector_windows.ext.exe`.

## Deploy via Fleet

Fleet's agent (`fleetd`/orbit) distributes custom extensions through a TUF
auto-update server and autoloads them. (Fleet Premium.)

1. Push each platform binary to your TUF repo:

   ```bash
   fleetctl updates add --path <TUF_repo> \
     --target build/agentic_detector_macos.ext \
     --name extensions/agentic_detector_macos --platform macos --version 0.1.0
   # repeat for linux / linux-arm64 / windows / windows-arm64
   ```

2. Reference them in `agent_options` (gitops or `fleetctl apply`):

   ```yaml
   agent_options:
     extensions:
       agentic_detector_macos:         { channel: 'stable', platform: 'macos' }
       agentic_detector_linux:         { channel: 'stable', platform: 'linux' }
       agentic_detector_linux_arm64:   { channel: 'stable', platform: 'linux-arm64' }
       agentic_detector_windows:       { channel: 'stable', platform: 'windows' }
       agentic_detector_windows_arm64: { channel: 'stable', platform: 'windows-arm64' }
   ```

3. Query like any built-in table (live query or scheduled query). Filtering on
   `kind` keeps it cheap (only the needed collectors run):

   ```sql
   -- remote MCP servers
   SELECT name, source, endpoint FROM agentic_software
     WHERE kind = 'mcp_server' AND location = 'remote';

   -- AI editor plugins
   SELECT name, identifier, version, category FROM agentic_software
     WHERE kind = 'ide_plugin' AND is_ai = 1;

   -- live AI/MCP egress + local inference listeners
   SELECT name, category, endpoint, port FROM agentic_software
     WHERE kind = 'socket';

   -- everything AI on the host, one query
   SELECT kind, name, category, running FROM agentic_software WHERE is_ai = 1;
   ```

## Local verification

```bash
make check                                     # gofmt + vet + race tests
AED_SMOKE=1 go test -run TestSmokeLiveHost -v ./tables/   # run generators against THIS host
```

Against a real osquery (requires `osqueryi` on PATH — `brew install --cask osquery`):

```bash
make run         # interactive osquery> shell with the extension loaded
make run-root    # same, as root (sees all users + all sockets, like fleetd)
make osq-verify  # one-shot: row counts per kind
```

Inside the `osquery>` shell: `.tables` lists tables, `.schema agentic_software`
shows columns, `.mode line` makes wide rows readable, then run any SQL. Exit
with `.exit`, `.quit`, or `Ctrl-D`.

Raw equivalent — note the two flags that matter:

```bash
osqueryi --allow_unsafe \
  --extension "$PWD/build/agentic_detector_macos.ext" \
  --extensions_require=agentic_detector --extensions_timeout=10 \
  "SELECT kind, name, category, running FROM agentic_software WHERE is_ai = 1"
```

- `--extensions_require=agentic_detector` — **required for one-shot queries**.
  Without it, `osqueryi "QUERY"` runs before the extension finishes its async
  registration and reports `no such table: agentic_software`. (Interactive
  `osquery>` sessions are fine without it — registration completes before you
  type.)
- `--allow_unsafe` — local testing only; in production osquery enforces
  root-owned, non-world-writable extension binaries.

## Security & limitations

- **No execution of discovered binaries** — versions come from manifests
  (`package.json`, pipx `dist-info`, Homebrew paths, `Info.plist`, registry).
- **No secret exposure** — the MCP `env_keys` field (in `detail`) lists env-var *names* only, never values.
- **Bounded** — project-config discovery walks a capped set of dev roots to a
  shallow depth, so arbitrary project locations are partial coverage.
- **Egress attribution is process-first** — a `socket` row is `ai-api-egress`
  because the *owning process* is an AI/agent tool, not because of the
  destination IP. Hosted-AI-API IPs are intentionally **not** matched: cloud
  providers share IPs across services, so IP-based attribution mislabels
  unrelated traffic. Loopback connections are treated as local IPC, not egress.
- **Multi-user as root** — when `fleetd` runs the extension as root it reads all
  users' homes; under an unprivileged run, unreadable homes yield partial rows
  rather than errors.
```
