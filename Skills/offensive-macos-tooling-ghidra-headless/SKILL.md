---
name: offensive-macos-tooling-ghidra-headless
description: >-
  Use when driving Ghidra headless from Cursor for macOS reverse engineering:
  opening Mach-O binaries, listing functions, decompiling by address, running
  custom Ghidra scripts, or doing breadth sweeps across many targets. Fires on
  "ghidra-mcp", "decompile with Ghidra", "run a Ghidra script", "list functions
  in this binary", and systemic-class scan setup.
folder: offensive-macos-tooling-ghidra-headless
source: skillz-wave2
trigger_phrases:
  - "ghidra-mcp"
  - "decompile with Ghidra"
  - "run a Ghidra script"
  - "Ghidra headless"
  - "list functions in this binary"
---

# Ghidra Headless — Tooling Skill

> **Channel boundary:** `REPO_MODE=analysis`. Root-cause analysis, lab reproduction,
> defensive mapping, and tooling guidance only. No operational exploit authoring
> against live third-party targets.

## When to use

- You need code-level static analysis of a Mach-O binary from Cursor: open/import, list functions, decompile, inspect strings, xrefs, types, or run a script.
- You are doing breadth work where one script must run over many daemons and emit stable TSV rows for triage.
- A hunt skill says "run the Ghidra script" or "decompile the candidate function"; this skill defines the exact MCP shape.

## Lab Topology — Where To Run This

| Step | Surface | How |
|------|---------|-----|
| Open/import binary | primary lab host | `ghidra-mcp` over SSH via `/Users/<remote-user>/bin/ghidra-mcp-launch` |
| List/decompile/analyze | Cursor | MCP tools such as `program.open`, `function.list`, `function.by_name`, `decomp.function` |
| Run hunt script | Cursor -> primary lab host | `ghidra.script` with scripts under `/Users/<remote-user>/ghidra-scripts/` |
| Cross-check metadata | primary lab host | `macre-vm-mcp` tools for entitlements, codesign, launchd, logs |
| Human visual depth work | lab-host GUI | Hopper may still be used manually, but it is not in the agent MCP loop |

Full topology: `Skills/offensive-macos-station-topology/SKILL.md`.

## Theory

Ghidra is now the station's primary agent-facing disassembler because it can be driven as a headless analysis engine. Cursor does not need a GUI click path: it starts a stdio MCP server over SSH, opens a program into a persistent Ghidra project, and keeps a `session_id` for follow-up calls.

The station uses `mrphrazer/ghidra-headless-mcp` pinned at commit `b9c491a6383dbc68c581e7fed16341ac47e7faba`. It exposes a real `pyghidra` backend, stdio transport, and about 212 tools. The richer `bethington/ghidra-mcp` plugin remains useful context, but this station's live path is the SSH-backed headless server.

Ghidra's first open of a binary is the expensive step. It imports the file, runs analyzers, discovers functions and strings, then returns a `session_id`. Reuse that session for every later `function.*`, `decomp.*`, `listing.*`, `symbol.*`, and `ghidra.script` call. Do not reopen the same binary for every question.

## Core MCP Tools

| Tool | Use |
|------|-----|
| `health.ping` | Prove the MCP process is reachable |
| `program.open` | Import/open a file and return `session_id` |
| `function.list` | Page through functions; use `query` to narrow |
| `function.by_name` | Resolve a named function or ObjC selector-like symbol |
| `decomp.function` | Return recovered C for a function start address |
| `listing.code_units.list` | Inspect disassembly/data around an address |
| `strings.list` or `search.*` tools | Find anchors when symbols are poor |
| `ghidra.script` | Run station scripts such as `scan_wrong_door.py` |

Confirm exact tool schemas with `tools/list` because the MCP server is pinned source, not a hand-written wrapper.

## Workflow A — Decompile One Function

1. Health check: call `health.ping`.
2. Open the binary:
   - Tool: `program.open`
   - Arguments: `path` from `CORPUS.md` `Lab Host Path Mapping`, `project_location="/Users/<remote-user>/ghidra-projects"`, `project_name="<program>-analysis"`, `read_only=true`, `update_analysis=true`
   - Output artifact: `session_id`
3. Find the target function:
   - If you know the name: `function.by_name(session_id, name, exact=false)`
   - If you are exploring: `function.list(session_id, query="<substring>", limit=50)`
4. Decompile:
   - Tool: `decomp.function`
   - Arguments: `session_id`, `function_start`, `timeout_secs=60`
   - Output artifact: recovered C plus Ghidra's function metadata
5. Record stable anchors in the findings repo: binary path, Ghidra project name, session target, function start, relevant strings/xrefs, and why this function matters.

## Workflow B — Breadth Sweep With A Script

1. Sync scripts to the primary lab host:

   ```bash
   scripts/install-ghidra-host.sh --install
   ```

2. For each target binary, call `program.open` once and retain the `session_id`.
3. Run the relevant script:
   - Wrong-door: `/Users/<remote-user>/ghidra-scripts/scan_wrong_door.py`
   - Defaults bypass: `/Users/<remote-user>/ghidra-scripts/scan_defaults_bypass.py`
   - Catalyst porting gap: `/Users/<remote-user>/ghidra-scripts/scan_catalyst_porting_gap.py`
   - Code-sign flags: `/Users/<remote-user>/ghidra-scripts/scan_flags_zero.py`
   - XPC listeners: `/Users/<remote-user>/ghidra-scripts/dump_xpc_listeners.py`
4. Save stdout TSV under the active findings repo, usually `findings/analysis/<date>-<class>-sweep.tsv`.
5. Rank candidates by evidence density, then use dynamic tools (`macre-vm-mcp`, LLDB, DTrace, ObjC harnesses) for proof or closure.

## Current Bug-Class Anchors

- Wrong-door bugs: entitlement or authorization checks landing on the wrong reachable interface. The Ghidra workflow finds listener/delegate/entitlement anchors before dynamic XPC probes.
- Media and parser attack surfaces where decompilation plus string/xref sweeps separate reachable code from dead exports.
- Logic bugs where platform or configuration branches flip a security decision. The Catalyst/defaults hunt scripts are shaped for this class.

## Pitfalls

- First analysis can be slow. Reuse the `session_id`; do not reopen per function.
- Function names may be synthetic (`FUN_...`). Use strings, xrefs, imports, and call graph edges to find semantic anchors.
- Swift and ObjC names may be partial or mangled. Pair Ghidra results with `nm`, `strings`, `class-dump`, or runtime probes.
- Script tools execute powerful code inside the analysis process. Keep scripts read-only unless the task explicitly requires mutation.
- `bethington/ghidra-mcp` advertises more GUI/plugin features, but its headless HTTP server is not the station's active path until its startup crash is resolved.

## Micro-Exercise

Goal: prove the station can decompile and run a hunt script.

1. Run:

   ```bash
   scripts/install-ghidra-host.sh --smoke
   ```

2. Expected result:
   - Java 21, Python 3.12, Ghidra 12.0.4, and `ghidra-headless-mcp` versions print.
   - The smoke opens `/bin/ls`, lists functions, decompiles the first function, and runs `scan_wrong_door.py`.
   - The script stdout includes the TSV header `daemon	listeners	ent_refs	should_accept_impls	audit_token_uses	evidence`.

Success means Cursor can use `ghidra-mcp` after MCP config reload.

## See Also

- `ghidra-scripts/README.md`
- `scripts/install-ghidra-host.sh`
- `Skills/offensive-macos-tooling-cli-static/SKILL.md`
- `Skills/offensive-macos-tooling-lldb/SKILL.md`
- `Skills/offensive-macos-station-topology/SKILL.md`
- Ghidra project: https://ghidra-sre.org/
