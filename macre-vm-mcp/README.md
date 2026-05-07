# macre-vm-mcp

Stdio MCP server running on the macOS RE lab host. Cursor on the
workstation reaches it via `ssh <lab-host> python -m macre_vm_mcp`.

Wraps VM-resident tooling as MCP tools:

| Module | Tool | Purpose |
|--------|------|---------|
| `tools_lldb` | `lldb_run` | scripted batch lldb run with breakpoints |
| `tools_lldb` | `lldb_break_and_inspect` | one-shot break + register/memory dump |
| `tools_lldb` | `lldb_run_anchors` | Gatehouse workflow from Ghidra anchors to LLDB stops |
| `tools_dtrace` | `dtrace_script` | run a D-script with timeout |
| `tools_dtrace` | `dtrace_oneliner` | run a single-line D expression |
| `tools_codesign` | `codesign_inspect` | parsed `codesign -dv` output |
| `tools_codesign` | `spctl_assess` | `spctl --assess --verbose` |
| `tools_codesign` | `entitlement_dump` | parsed entitlement plist |
| `tools_system` | `log_stream` | `log stream --predicate` with timeout |
| `tools_system` | `launchctl_list` | `launchctl list` |
| `tools_system` | `launchctl_print` | `launchctl print <service-target>` |

## VM install

Requires Python 3.10+. On the lab VM:

```bash
/opt/homebrew/bin/python3 -m venv ~/.venvs/macre-vm-mcp
~/.venvs/macre-vm-mcp/bin/pip install --upgrade pip
~/.venvs/macre-vm-mcp/bin/pip install /path/to/macre-vm-mcp
```

Workstation-side install is optional (useful for tests and dev). The
deployment script `scripts/deploy-macre-vm-mcp.sh` handles this end-to-end.

## Cursor registration

Add to `~/.cursor/mcp.json`:

```json
"macre-vm-mcp": {
  "command": "ssh",
  "args": [
    "-o", "BatchMode=yes",
    "-o", "ServerAliveInterval=30",
    "<lab-host>",
    "/Users/<remote-user>/.venvs/macre-vm-mcp/bin/python",
    "-m", "macre_vm_mcp"
  ],
  "env": {}
}
```

Restart Cursor's MCP connections; `macre-vm-mcp` tools should appear in
the agent's tool list.
