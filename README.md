<div align="center">

```
  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝
  ███████╗████████╗ █████╗  ██████╗██╗  ██╗
  ██╔════╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
  ███████╗   ██║   ███████║██║     █████╔╝
  ╚════██║   ██║   ██╔══██║██║     ██╔═██╗
  ███████║   ██║   ██║  ██║╚██████╗██║  ██╗
  ╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
```

**Discovery & risk analytics for shadow-AI infrastructure**

Find the un-audited MCP servers, Claude skills, sub-agents and Cursor rules on your hosts — score them, map them to MITRE ATT&CK and the OWASP LLM Top 10, and hand the results to a human *or an agent* for remediation.

</div>

---

## Table of contents

- [What it is](#what-it-is)
- [Why shadow AI is a problem](#why-shadow-ai-is-a-problem)
- [How it works](#how-it-works)
  - [Discovery](#1-discovery)
  - [Rules & severity](#2-rules--severity)
  - [MITRE ATT&CK / OWASP mapping](#3-mitre-attck--owasp-mapping)
  - [Risk scoring](#4-risk-scoring)
  - [Finding identity, baselines & diffing](#5-finding-identity-baselines--diffing)
- [Install](#install)
- [Quick start](#quick-start)
- [Program options](#program-options)
  - [Core](#core)
  - [Targeting (MCP)](#targeting-mcp)
  - [Network tuning & politeness (MCP)](#network-tuning--politeness-mcp)
  - [Filesystem walk (skills)](#filesystem-walk-skills)
  - [Filtering, gating & state](#filtering-gating--state)
  - [Configuration & logging](#configuration--logging)
- [Output formats](#output-formats)
- [Exit codes](#exit-codes)
- [Usage recipes](#usage-recipes)
- [License & status](#license--status)

---

## What it is

ShadowStack is a single, dependency-light static binary that **inventories AI-agent attack surface** and assigns it security risk. It speaks two protocols:

| Protocol | Flag | What it scans | Where |
|---|---|---|---|
| **MCP** (Model Context Protocol) | `--protocol mcp` | MCP-compliant servers — speaks JSON-RPC `initialize`, enumerates `tools` / `resources` / `prompts`, captures TLS + HTTP banners | the network (IPv4 CIDRs, hosts, DNS names) |
| **Skills** | `--protocol skills` | Claude skills, sub-agents, slash commands, `CLAUDE.md` / `AGENTS.md`, Cursor / Windsurf / Cline rules, MCP client configs, hooks, **and live stdio MCP processes** | the local filesystem + `/proc` |

Every run produces an **inventory** (what exists) and a **findings list** (what's risky), rendered for a human (ASCII) or a machine (JSON / NDJSON / SARIF / CSV). All output carries stable rule IDs, dedup fingerprints, remediation text, and ATT&CK/OWASP references — so results are equally ingestible by a SIEM, a code-scanning dashboard, or an AI agent tasked with remediation.

## Why shadow AI is a problem

AI infrastructure is being deployed *inside* organizations faster than security teams can govern it:

- **It's invisible to traditional tooling.** EDR/CASB products reason about packets and processes from a *user's* perspective. They don't enumerate an MCP server's exposed tool surface, read a sub-agent's tool grants, or notice that a `CLAUDE.md` quietly instructs every session to exfiltrate to a webhook. The AI surface stays un-inventoried until something already went wrong on the wire.
- **It's un-audited and un-managed.** Developers stand up MCP servers on dev ports, drop skills into `~/.claude`, and wire Cursor rules into repos — none of it known to IT, none of it access-controlled, much of it cleartext on the LAN. That's *shadow AI*: real capability, zero governance.
- **It's a live injection & RCE surface.** Skills, sub-agents and server `instructions` fields are natural-language code that an LLM executes with the user's privileges. They can carry prompt/command injection, meta-context that hijacks the model's reasoning, embedded secrets, over-broad tool grants, auto-approve directives, and outright RCE / persistence / privilege-escalation payloads — often *concealed* with zero-width characters, bidi overrides, Unicode tag-blocks, ANSI escapes, or base64 blobs.
- **Compromise hides here well.** A malicious skill or a rug-pull MCP server (one that mutates its tool surface *after* the client approves it) is an attractive, low-noise foothold. Inter-agent persuasion can erode safety boundaries that each agent enforces in isolation.

ShadowStack exists to make that surface **discoverable, rankable, and remediable** before it's abused.

## How it works

### 1. Discovery

**MCP (network).** Resolves `--target` specs (CIDRs / IPv4s / DNS names) into a de-duplicated host list, then drives a configurable worker pool. Per host/port it: detects HTTP vs. TLS, pulls `GET /.well-known/mcp` discovery docs, probes both Streamable-HTTP and SSE transports, performs the JSON-RPC `initialize` handshake (retrying `2025-06-18` → `2024-11-05` for stricter servers), and paginates `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list`. A `401` + `WWW-Authenticate: Bearer` challenge is recorded as a **suspected** (auth-gated) MCP host so an access-controlled server still lands in the inventory. TLS is intentionally *not* validated — a self-signed/expired/internal cert is captured as a **finding**, not a connection error, because the scanner must inventory hosts regardless of cert hygiene.

**Skills (filesystem + process).** Walks the standard user/project roots (`~/.claude`, `~/.cursor`, `./.claude`, plugin bundles, `.mcp.json` / `claude_desktop_config.json` / VS Code MCP configs, `CLAUDE.md` / `AGENTS.md` / `.windsurf` / `.clinerules`, …) up to `--walk-depth`, parsing frontmatter, body prose, bundled scripts, hooks and MCP-client config. On Linux it *also* reads `/proc` to inventory **running** stdio MCP servers (npx `@modelcontextprotocol/*`, `uvx`/`pipx`/`bunx` runners, `python -m mcp_server_*`, `mcp-server`/`mcp-proxy` binaries, node/bun/deno scripts) — the "what's executing right now" view that static config can't give.

### 2. Rules & severity

Each protocol has a rules engine of independent, per-category evaluators. Every rule emits a `Finding` with a **severity** and a stable dotted **category**:

| Severity | Meaning |
|---|---|
| **High** | Active exposure or a credible exploitation primitive (RCE-capable tool, secret leak, off-loopback weak session ID, SSRF seed, …) |
| **Medium** | Risky configuration or a meaningful weakening (cleartext transport, over-broad capability/scope, expired cert, …) |
| **Low** | Inventory / hygiene signal worth knowing (server identity, listed resource, benign keyword hit) |

MCP categories cover `transport`, `tls`, `auth`, `identity`, `capabilities`, `instructions`, `tool`, `resource`, `prompt`, `banner`, `discovery` (suspected hosts), and multi-signal `correlation` chains (e.g. `correlation.rug_pull_surface`, cross-server `tool_name_shadowing`). Skills categories cover filesystem `metadata`, `frontmatter`, `directive`, `content` (URLs/IPs/scripts/commands/keywords + concealment: hidden-unicode / ANSI / encoded-blob), `hook`, `mcpconfig`, live `process`, and `correlation` TTP chains (generic / linux / windows).

Operators can suppress accepted findings with an [`--allow-list`](#filtering-gating--state); suppression happens *before* scoring so waived findings never inflate a target's risk.

### 3. MITRE ATT&CK / OWASP mapping

After the rules run, every finding is enriched (by category prefix) with a **remediation recommendation** and **references** into the [OWASP LLM Top 10 (2025)](https://genai.owasp.org/) and [MITRE ATT&CK](https://attack.mitre.org/). Representative mappings:

| Category prefix | OWASP LLM | MITRE ATT&CK |
|---|---|---|
| `transport` | LLM02 | T1133 (External Remote Services) |
| `tls` | LLM02 | T1573 (Encrypted Channel) |
| `auth` | LLM06 | T1190 (Exploit Public-Facing App) |
| `instructions` | LLM01, LLM07 | — |
| `tool` | LLM06 | T1059 (Command & Scripting Interpreter) |
| `banner` | LLM02 | T1592 (Gather Victim Host Info) |
| `hook` / `mcpconfig` (skills) | LLM06 | T1059 / T1552 (Unsecured Credentials) |
| `metadata` (skills) | LLM03 | T1222 (File/Dir Permissions Mod.) |

References travel with the finding through *every* output format, so a SARIF result, an NDJSON line and a CSV row all carry the same ATT&CK technique IDs.

### 4. Risk scoring

Findings answer "what's wrong"; risk scoring answers "**which target is most dangerous**". Each target's findings fold into a single weighted score:

```
score = 10·(High count) + 4·(Medium count) + 1·(Low count)
```

Weights are spread an order of magnitude apart on purpose — a single High outranks any realistic pile of Lows, so a noisy-but-benign file can't overtake a genuinely dangerous host. The score maps to a coarse **band** for at-a-glance triage:

| Band | Score | Roughly |
|---|---|---|
| `none` | 0 | clean |
| `low` | 1–3 | a few Lows |
| `medium` | 4–9 | a Medium (or several Lows) |
| `high` | 10–24 | a High present |
| `critical` | 25+ | ~3+ Highs' worth |

The ranking (highest first, ties broken on the target key for reproducible output) appears in both the ASCII and JSON renderers, keyed per host `ip:port` (MCP) or per file path (skills).

### 5. Finding identity, baselines & diffing

- **Rule IDs** — every finding gets a stable, greppable `SS-MCP-…` / `SS-SKL-…` derived (FNV-1a) from its category, so a rule has a fixed handle without a hand-maintained registry.
- **Fingerprints** — a deterministic per-finding hash of `rule + target + evidence`, so re-scans can dedup and diff. (A live MCP *process* fingerprints on the executable + launch command, keeping a stable identity across restarts — the volatile pid lives only in the detail text.)
- **Baseline / diff** — `--baseline prev.<json|ndjson|sarif|csv>` emits only findings **new** since a prior report (the delta). The loader is format-agnostic — a baseline captured in one format diffs cleanly against a scan emitted in another — and the filter runs before both rendering *and* the `--fail-on` gate.

## Install

ShadowStack is a single static binary — drop it on a box and run it.

## Quick start

```sh
# Discover MCP servers on a /24, human-readable
shadowstack --protocol mcp --target 192.168.1.0/24

# Audit the local Claude/Cursor AI surface, JSON to a file
shadowstack --protocol skills --format json --output skills.json

# CI gate: fail the build if anything High turns up on the local surface
shadowstack -p skills --fail-on high -f sarif -o results.sarif
```

> Banner and progress go to **stderr**; the report goes to **stdout** (or `--output`). 

## Program options

### Core

| Flag | Default | Description |
|---|---|---|
| `-p, --protocol <mcp\|skills>` | `mcp` | Which engine to run: `mcp` (network discovery) or `skills` (filesystem + process). |
| `-f, --format <fmt>` | `ascii` | Output format: `ascii`, `json`, `ndjson`, `sarif`, `csv`. See [Output formats](#output-formats). |
| `-o, --output <path>` | *stdout* | Write the report to a file instead of stdout. |
| `-h, --help` / `-V, --version` | — | Standard help / version. |

### Targeting (MCP)

| Flag | Default | Description |
|---|---|---|
| `-c, --target <spec>` (alias `--cidr`) | `127.0.0.1/32` | Scan target(s): any mix of CIDR blocks (`192.168.1.0/24`), bare IPv4s (`10.0.0.5`), and DNS hostnames (resolved to IPv4 at scan start). Repeatable and comma-separated; specs are merged and de-duplicated. |
| `--targets-file <path>` | — | Read additional targets from a file, one spec per line (`#` comments and blanks ignored). Merged with `--target`. |
| `--ports <list>` | built-in set¹ | Comma-separated TCP ports to probe. |

¹ Default port set: `80, 443, 6274, 6280, 8765, 8787, 3000, 3001, 3030, 5173, 5174, 5000, 5001, 8000, 8001, 8008, 8080, 8081, 8082, 8443, 8888, 18080, 28080, 4000, 7000, 9000, 9090, 11434` — standard HTTP/HTTPS, MCP-specific ports, common Node/Python/Vite/Flask dev ports, generic HTTP-alt, and AI tooling (e.g. Ollama `11434`).

### Network tuning & politeness (MCP)

| Flag | Default | Description |
|---|---|---|
| `--connect-timeout <ms>` | `800` | TCP connect timeout. |
| `--http-timeout <ms>` | `1500` | HTTP request timeout (`initialize` / list calls). |
| `--workers <n>` | `32` | Parallel scan workers (controls *parallelism*, not per-host pressure). |
| `--max-duration <secs>` | `0` (off) | Global wall-clock budget. When it lapses, workers stop taking new work and the scan renders what it has (a `scan deadline reached` note is added). Bounds the runtime of a large sweep regardless of host count. |
| `--per-host-delay <ms>` | `0` (off) | Minimum spacing between connection attempts to a *single* host. Caps the rate any one target sees without throttling the whole sweep. |
| `--connect-retries <n>` | `0` (off) | Retry a failed TCP connect this many times before giving up. |
| `--connect-backoff <ms>` | `100` | Base backoff between connect retries; doubles each retry (100 → 100, 200, 400…). Only matters with `--connect-retries`. |

### Filesystem walk (skills)

| Flag | Default | Description |
|---|---|---|
| `--walk-depth <n>` | `4` | Maximum directory recursion depth for the skills walker. Bounds runtime and guards against pathological/malicious trees. |

### Filtering, gating & state

| Flag | Default | Description |
|---|---|---|
| `--allow-list <file>` | — | Suppression override. Findings matching a rule are dropped before rendering (the suppressed count is still reported). One rule per line: `<category-glob> [<target-glob>]`; `#` comments, `*` wildcard. `target` matches an MCP host `ip:port` or a skills file path. |
| `--fail-on <high\|medium\|low>` | — | Exit non-zero (code `2`) when a finding at or above this tier is present. For CI/CD gating. Unset = always exit `0` on a successful scan. |
| `--baseline <file>` | — | Diff mode: a prior report (`json`/`ndjson`/`sarif`/`csv`). Findings already present in the baseline are dropped, so the scan emits only what's **new**. `--fail-on` then gates on the delta. |
| `--resume <file>` | — | Checkpoint/journal for large CIDR sweeps (**MCP only**). Completed hosts are journalled as the scan runs; re-running against the same file skips them. The file pins the scan's identity (targets/ports/protocol) — resuming with different values is rejected. |

**Allow-list example:**

```sh
# accept all heuristic keyword hits (reviewed, expected in this repo)
keyword.*
# drop a specific category only on one host (any port)
tool.dangerous_name        10.0.0.5*
# whole-file waiver for a known-safe artifact
*                          */known-safe/CLAUDE.md
```

### Configuration & logging

| Flag | Default | Description |
|---|---|---|
| `--config <file.toml>` | — | TOML scan profile pinning flags into a version-controllable file. Keys mirror the long flags (`--connect-timeout` → `connect-timeout`). Precedence: **CLI flag > profile value > built-in default**, decided per field. Parsing is strict (unknown/duplicate key or `[table]` header → hard error). |
| `-v, --verbose` | — | Increase verbosity. Repeatable: `-v` = DEBUG (resolved options, port list), `-vv` = TRACE. |
| `-q, --quiet` | — | Decrease verbosity. Repeatable: `-q` = warnings + errors only, `-qq` = errors only (also hides the banner). `-v`/`-q` cancel out. |

Verbosity is a baseline of `INFO` shifted by `-v`/`-q`. All diagnostics go to stderr as timestamped, level-tagged records; stdout stays the report alone. Use `-q` in cron/CI when only the report file and exit code matter.

## Output formats

| Format | Contents | Best for |
|---|---|---|
| `ascii` | Full inventory + risk ranking + findings table, human-readable (long fields truncated with `…`) | interactive use, terminals |
| `json` | The complete document — inventory, per-target risk, and findings with full untruncated strings (schema `1.3`) | `jq`, dashboards, agent ingestion |
| `ndjson` | One finding object per line, each with `rule_id` + `fingerprint` + refs | SIEM / log pipelines (Splunk, Elastic, Loki) |
| `sarif` | SARIF 2.1.0 (unique rule descriptors, severity→level, `partialFingerprints`) | GitHub code-scanning, Azure DevOps, SAST tooling |
| `csv` | RFC-4180 rows | spreadsheet triage |

The three findings-only formats (`ndjson`/`sarif`/`csv`) carry the findings and their identity, not the full server/skill inventory that `ascii`/`json` emit.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed successfully (no `--fail-on` tier tripped). |
| `2` | `--fail-on` gate tripped — a finding at/above the threshold is present. |
| `1` | Pipeline error (bad config, unreadable allow-list/baseline, etc.). |

## Usage recipes

```sh
# Single host, custom ports, tight timeouts
shadowstack -p mcp -c 10.0.0.5/32 --ports 8080,8443,11434 \
  --connect-timeout 300 --http-timeout 800

# Mixed targets: two CIDRs, a host, and a DNS name
shadowstack -p mcp --target 10.0.0.0/24,192.168.1.0/24 \
  --target 10.1.2.3 --target mcp.internal

# Pull the scope from a file, JSON output
shadowstack -p mcp --targets-file scope.txt --format json -o out.json

# Aggressive parallel /22 sweep (opens many sockets — be considerate)
shadowstack -p mcp -c 10.10.0.0/22 --workers 128

# Polite, resilient sweep: 5-min budget, 250ms/host throttle, retry flaky connects
shadowstack -p mcp -c 10.10.0.0/22 --max-duration 300 \
  --per-host-delay 250 --connect-retries 2 --connect-backoff 100

# Resumable /16: time-box each run, re-run to continue where it stopped
shadowstack -p mcp -c 10.10.0.0/16 --max-duration 1800 --resume sweep.ckpt

# Recurring org scan: emit only findings new since last week's report
shadowstack -p mcp -c 10.0.0.0/24 --baseline last-week.json --format ndjson

# Repeatable CI sweep pinned in a profile, overriding worker count on the fly
shadowstack -p mcp --config ci-mcp.toml --workers 8

# Audit the local AI surface and gate CI on High findings
shadowstack -p skills --fail-on high -f sarif -o results.sarif
```

## License

ShadowStack (the scanner) is licensed under the **[Apache License, Version 2.0](LICENSE)** — a permissive license with an explicit patent grant. You are free to use, modify, and distribute the binary and source, including in commercial settings, provided you retain the license and attribution notices.

```
Copyright 2026 ShadowStack
Licensed under the Apache License, Version 2.0.
```
