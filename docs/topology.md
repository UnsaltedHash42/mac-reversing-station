# Station Topology — Reference

This is the reference map for the macOS bug-hunting station. The user-facing workflow lives in `docs/operator-guide.md`.

## Diagram

```mermaid
flowchart LR
    subgraph Workstation["Mac Workstation - cockpit"]
        Cursor["Cursor IDE + Agent"]
        MCP["~/.cursor/mcp.json"]
        Skillz["~/tools/skillz"]
        Findings["~/re/<program> findings repos"]
    end

    subgraph Lab["Lab machines"]
        Primary["primary: NightBlood<br/>Ghidra 12.0.4<br/>ghidra-mcp<br/>macre-vm-mcp<br/>Hopper manual only"]
        Crash["crash-test<br/>operator adds"]
        Cross["cross-platform Apple Silicon<br/>operator adds"]
        Intel["intel-baseline<br/>operator adds"]
    end

    Cursor --> MCP
    MCP -->|"ssh stdio ghidra-mcp"| Primary
    MCP -->|"ssh stdio macre-vm-mcp"| Primary
    Cursor --> Skillz
    Cursor --> Findings
    Cursor -.->|"ssh direct"| Crash
    Cursor -.->|"ssh direct"| Cross
    Cursor -.->|"ssh direct"| Intel
```

## Host Roles

| Role | Current Alias | Purpose |
|------|---------------|---------|
| primary | `NightBlood` | Static analysis, Ghidra headless, routine XPC/log/debug probes |
| crash-test | operator to fill | Panics, destructive daemon tests, fuzzing |
| cross-platform | operator to fill | Different Apple Silicon generation verification |
| intel-baseline | operator to fill | x86_64/macOS comparison |

NightBlood is the only required host for Wave 2. The other roles improve evidence quality and submission confidence.

## MCP Servers

### `ghidra-mcp`

Cursor launches:

```json
"ghidra-mcp": {
  "command": "ssh",
  "args": [
    "-o", "BatchMode=yes",
    "-o", "ServerAliveInterval=30",
    "NightBlood",
    "/Users/szeth/bin/ghidra-mcp-launch"
  ],
  "env": {}
}
```

NightBlood components:

- Java: `/Users/szeth/Applications/jdk-21.0.11+10/Contents/Home`
- Ghidra: `/Users/szeth/Applications/ghidra_12.0.4_PUBLIC`
- MCP source: `/Users/szeth/tools/ghidra-headless-mcp`
- MCP venv: `/Users/szeth/.venvs/ghidra-headless-mcp`
- Hunt scripts: `/Users/szeth/ghidra-scripts`
- Ghidra projects: `/Users/szeth/ghidra-projects`

Verification:

```bash
scripts/install-ghidra-host.sh --smoke
```

### `macre-vm-mcp`

Cursor launches:

```json
"macre-vm-mcp": {
  "command": "ssh",
  "args": [
    "-o", "BatchMode=yes",
    "-o", "ServerAliveInterval=30",
    "NightBlood",
    "/Users/szeth/.venvs/macre-vm-mcp/bin/python",
    "-m", "macre_vm_mcp"
  ],
  "env": {}
}
```

Use it for LLDB, DTrace, codesign, entitlements, launchd, and logs.

## Hopper Status

Hopper is retired from the agent MCP loop. The old Hopper bridge entry should be absent from `~/.cursor/mcp.json`.

Hopper may remain installed on NightBlood for manual GUI depth work. Do not make agent workflows depend on Hopper menus, plugin injection, or document-loaded state.

## Files That Define The Station

| Path | Purpose |
|------|---------|
| `scripts/install-ghidra-host.sh` | Install/check/smoke Ghidra + headless MCP on NightBlood |
| `ghidra-scripts/` | Read-only hunt scripts synced to NightBlood |
| `macre-vm-mcp/` | VM-side dynamic tooling MCP server |
| `templates/findings-repo/` | Private research repo starter with authorization, lab safety, corpus, metrics, and reporting templates |
| `docs/ontology/` | Shared macOS vulnerability-class ontology |
| `docs/playbooks/` | Third-party app family playbooks |
| `Skills/offensive-macos-*` | Cursor skills for tooling, hunts, ontology, playbooks, discipline, lab, and reporting |
| `docs/operator-guide.md` | How to use the station |

## Health Checks

```bash
ssh -o BatchMode=yes NightBlood true
python3 -m json.tool ~/.cursor/mcp.json >/dev/null
scripts/install-ghidra-host.sh --smoke
tests/ghidra-scripts/smoke.sh
python3 scripts/validate_workstation_bundles.py
```

Wave 3 adds `scripts/smoke-wave3.sh` for structural station-release checks. Its live mode may call the NightBlood and Ghidra smoke paths above.

## Failure Boundaries

- SSH failure: fix `~/.ssh/config` or key auth first.
- `ghidra-mcp` failure: run `scripts/install-ghidra-host.sh --smoke`.
- Script missing: rerun `scripts/install-ghidra-host.sh --install` to sync `ghidra-scripts/`.
- Dynamic tool failure: run `scripts/deploy-macre-vm-mcp.sh`.
- Cursor tool list stale: restart Cursor after editing `~/.cursor/mcp.json`.
