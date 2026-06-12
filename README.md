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

## Example queries

Run these in the `osquery>` shell (`make run`), or one-shot by passing the
`SELECT` as the last arg to `osqueryi` with the flags from
[Local verification](#local-verification).

```sql
-- shell dot-commands (shell only, not one-shot):
.tables agentic_software        -- confirm the table registered
.schema agentic_software        -- list columns
.mode line                      -- readable output for wide rows

-- counts per kind
SELECT kind, count(*) FROM agentic_software GROUP BY kind;

-- everything classified AI on the host
SELECT kind, name, category, running FROM agentic_software WHERE is_ai = 1 LIMIT 20;

-- outbound AI/MCP connections — where data is going
SELECT name, endpoint FROM agentic_software WHERE kind = 'socket' AND location = 'remote';

-- running MCP servers, local stdio vs remote
SELECT name, source AS client, location, running, pid
  FROM agentic_software WHERE kind = 'mcp_server' AND running = 1;

-- AI editor plugins with versions
SELECT name, identifier, version, category
  FROM agentic_software WHERE kind = 'ide_plugin' AND is_ai = 1;

-- pull a kind-specific extra out of the JSON detail column
SELECT name, json_extract(detail, '$.transport') AS transport, endpoint
  FROM agentic_software WHERE kind = 'mcp_server';
```

`.tables`/`.schema`/`.mode` are osquery shell dot-commands — they only work
inside the interactive shell, not as a one-shot query string. The `SELECT`s work
both ways. Filtering on `kind` keeps queries cheap: only the matching collectors
run (constraint pushdown).

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

Sign the binaries before distributing or running a downloaded copy — see
[Signing & trust](#signing--trust) below.

## Download a prebuilt binary

Each [release](https://github.com/karmine05/agentic-detector/releases) attaches
the five platform binaries plus `SHA256SUMS`. Downloading needs the
[`gh`](https://cli.github.com) CLI (the repo is private).

| Platform | Asset |
|---|---|
| macOS (Intel + Apple Silicon) | `agentic_detector_macos.ext` (universal) |
| Linux x86-64 | `agentic_detector_linux.ext` |
| Linux ARM64 | `agentic_detector_linux_arm64.ext` |
| Windows x86-64 | `agentic_detector_windows.ext.exe` |
| Windows ARM64 | `agentic_detector_windows_arm64.ext.exe` |

The binaries are **not code-signed**, so a downloaded copy is quarantined —
clear it (below) or sign it ([Signing & trust](#signing--trust)).

**macOS** — download → clear quarantine → run:

```bash
gh release download v0.1.0 -R karmine05/agentic-detector -p 'agentic_detector_macos.ext'
xattr -d com.apple.quarantine agentic_detector_macos.ext   # unsigned → clear quarantine
osqueryi --allow_unsafe --extension "$PWD/agentic_detector_macos.ext" \
  --extensions_require=agentic_detector --extensions_timeout=10 \
  "SELECT kind, count(*) FROM agentic_software GROUP BY kind"
```

**Linux** (use `_linux_arm64.ext` on ARM):

```bash
gh release download v0.1.0 -R karmine05/agentic-detector -p 'agentic_detector_linux.ext'
chmod +x agentic_detector_linux.ext
osqueryi --allow_unsafe --extension "$PWD/agentic_detector_linux.ext" \
  --extensions_require=agentic_detector --extensions_timeout=10 \
  "SELECT kind, count(*) FROM agentic_software GROUP BY kind"
```

**Windows** (PowerShell; use `_windows_arm64.ext.exe` on ARM):

```powershell
gh release download v0.1.0 -R karmine05/agentic-detector -p 'agentic_detector_windows.ext.exe'
Unblock-File agentic_detector_windows.ext.exe
osqueryi.exe --allow_unsafe --extension "$PWD\agentic_detector_windows.ext.exe" `
  --extensions_require=agentic_detector --extensions_timeout=10 `
  "SELECT kind, count(*) FROM agentic_software GROUP BY kind"
```

Verify integrity before running:

```bash
gh release download v0.1.0 -R karmine05/agentic-detector -p SHA256SUMS
shasum -a 256 -c SHA256SUMS      # Linux: sha256sum -c SHA256SUMS
```

`--extensions_require` / `--allow_unsafe` are explained in
[Local verification](#local-verification); more queries in
[Example queries](#example-queries).

## Signing & trust

Two **separate** things gate running the extension — don't conflate them:

1. **OS trust (signing)** — macOS Gatekeeper / Windows SmartScreen block
   *downloaded, unsigned* binaries from executing. This is what code-signing
   solves.
2. **osquery's load check** — osquery refuses to autoload an extension that is
   world-writable or not owned by root/Administrator (independent of any
   signature), unless you pass `--allow_unsafe`. Covered at the end.

The release binaries are unsigned. Sign per platform before distribution; for a
one-off local run you can ad-hoc sign (below) or just clear quarantine
(`xattr -d com.apple.quarantine …` / `Unblock-File …`).

### macOS

```bash
# (a) Local / ad-hoc — enough to run on this machine. Also re-stamps the
#     signature that `lipo` invalidates when it fuses the two arch slices.
codesign --force --sign - agentic_detector_macos.ext
codesign -dv --verbose=2 agentic_detector_macos.ext        # verify

# (b) Distribution (other Macs / MDM) — Developer ID + notarization.
codesign --force --options runtime --timestamp \
  --sign "Developer ID Application: <ORG> (<TEAMID>)" agentic_detector_macos.ext
ditto -c -k agentic_detector_macos.ext ext.zip             # notarize a container
xcrun notarytool submit ext.zip --apple-id <id> --team-id <TEAMID> \
  --password <app-specific-password> --wait
```
A standalone Mach-O can't be stapled (no container) — the notarization ticket is
checked online at first launch, or staple the distribution package instead. For
fleetd/MDM autoload the binary is placed on disk by the agent (not quarantined),
so Developer ID signing is recommended but notarization isn't strictly required.

### Windows (Authenticode)

```powershell
# Production cert:
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a `
  agentic_detector_windows.ext.exe
signtool verify /pa agentic_detector_windows.ext.exe        # verify

# Dev / self-signed (testing only):
$c = New-SelfSignedCertificate -Type CodeSigningCert `
  -Subject "CN=agentic-detector-dev" -CertStoreLocation Cert:\CurrentUser\My
Set-AuthenticodeSignature agentic_detector_windows.ext.exe -Certificate $c
```

### Linux

No OS-level code signature is needed to execute. Trust is established by
checksum (and optionally a detached GPG signature over the artifact):

```bash
sha256sum -c SHA256SUMS
gpg --detach-sign --armor agentic_detector_linux.ext        # optional, publisher-side
gpg --verify agentic_detector_linux.ext.asc                 # consumer-side
```

### osquery load permissions (all platforms)

Before a production autoload (without `--allow_unsafe`):

```bash
# macOS / Linux — root-owned, not world-writable, parent dir likewise
sudo chown root agentic_detector_*.ext && sudo chmod 755 agentic_detector_*.ext
```
Windows: the `.ext.exe` and its parent directory must be owned by
Administrators with inheritance disabled. fleetd/orbit handles this placement
automatically when it deploys the extension.

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
