---
name: offensive-macos-gatehouse-ghidra-lldb
description: >-
  Use when carrying Ghidra-derived symbols, functions, or addresses into LLDB
  confirmation and writing the dynamic result back to project evidence.
folder: offensive-macos-gatehouse-ghidra-lldb
source: skillz-wave4
trigger_phrases:
  - "bridge ghidra lldb"
  - "ghidra to lldb"
  - "lldb anchors"
  - "confirm this static anchor"
---

# Gatehouse — Ghidra To LLDB

> **Channel boundary:** `REPO_MODE=analysis`. Gatehouse confirms static hypotheses
> in a lab-safe way. It does not start dynamic testing until `LAB_SAFETY.md`
> permits the host, user, rollback, and test shape.

## When To Use

- A Ghidra function, symbol, or address needs runtime confirmation.
- A source/Electron/dossier claim has a concrete binary anchor.
- Static and dynamic notes are starting to diverge.

## Workflow

1. Read `LAB_SAFETY.md`, `CORPUS.md`, the dossier, and the relevant Ghidra evidence path.
2. Prefer symbol anchors when available. Treat raw addresses as uncertain until image slide and architecture slice are verified.
3. Use `ghidra-scripts/export_lldb_anchors.py` or a Ghidra MCP query to collect anchors.
4. Use `macre-vm-mcp` `lldb_run_anchors` or `lldb_run` to capture image list, registers, backtrace, and targeted memory/state.
5. Save the transcript under `artifacts/` or `findings/analysis/`, then update Scriptorium and `HANDOFF.md`.

## Stop And Ask Before

- Attaching to a running PID.
- Running GUI apps, daemons, helpers, installers, or updaters.
- Ignoring slide, slice, SIP, timeout, or symbol-resolution uncertainty.

## See Also

- `macre-vm-mcp/src/macre_vm_mcp/tools_lldb.py`
- `ghidra-scripts/export_lldb_anchors.py`
- `Skills/offensive-macos-tooling-lldb/SKILL.md`
- `Skills/offensive-macos-scriptorium-evidence/SKILL.md`
