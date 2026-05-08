# macOS Reversing Station

A reverse-engineering setup for macOS where an LLM agent (Cursor, Claude Code, anything that speaks MCP) drives Ghidra and lldb on a separate Mac, keeps its own evidence ledger, and lets you focus on the actual hard parts.

You drop a binary path. The agent runs intake, picks a recipe, sweeps the binary, triages candidates, confirms anchors in lldb, and writes everything down. You decide whether the candidates are real.

Built for authorized work: red team research, vulnerability research, defensive validation, root cause analysis, reporting. PoCs and chain artifacts live in private project clones. This template stays public.

## How it works

Two machines. A workstation (your Mac, where you run the agent) and a lab host (a separate Mac or VM where Ghidra and dynamic tools live). The agent on the workstation talks to two MCP servers over SSH: `ghidra-mcp` for static analysis, `macre-vm-mcp` for codesign / lldb / dtrace / log capture / OS metadata.

The loop:

```
intake -> watch -> recipe -> scan -> triage -> confirm -> record
                    ^                                       |
                    +---------------------------------------+
```

Each step writes a file. Intake produces a dossier. Watch reads the dossier and picks a recipe. The recipe runs Ghidra scripts that emit anchor TSVs. Triage promotes anchors into candidate JSON files. Lldb confirms one. The closure rationale lands in the scriptorium with a hash of the binary slice that produced the evidence.

## Try it for 30 minutes

Two tutorials, pick one:

- [docs/tutorial/first-pass-tccd.md](docs/tutorial/first-pass-tccd.md) — one full lap against `tccd` (on every Mac, real surface, not exploitable through anything in the tutorial).
- [docs/tutorial/first-pass-planted.md](docs/tutorial/first-pass-planted.md) — a purpose-built XPC daemon with three planted bugs. Demonstrates triage selectivity: find three candidates, close the red herring, escalate the real ones.

After either tutorial the rest of the doc tree is navigable.

## Going hunting

If you've reversed macOS targets before, the mental model is:

Pick a target queue. Privileged helpers and enterprise agents pay best. OS-component daemons next. TCC-heavy consumer apps after that. Playbooks for each shape live in [`docs/playbooks/`](docs/playbooks/).

Run intake on every binary even if it's cheap. Surfaces show up that the file's path does not.

Run the relevant scan scripts. Each emits a TSV with three tiers of evidence: A is callsite-verified (use it directly in lldb), B is Mach-O / ObjC metadata, C is string heuristic. Triage A first.

Maintain candidate hygiene. Every row converges to `closed`, `escalated`, or `blocked`. Closures with rationale are research output and count.

Chain discovery is its own skill. Two confirmed primitives, exploitability rating, one experiment. See `Skills/offensive-macos-chain-discovery/SKILL.md`.

The hunts you'll reach for, paired with their scan scripts:

| Hunt | What it covers |
|---|---|
| `hunt-wrong-door` | XPC daemons trusting clients they should validate |
| `hunt-defaults-bypass` | Security checks gated on user-writable defaults |
| `hunt-catalyst-porting-gap` | iOS-style entitlement assumptions that didn't survive the macOS port |
| `hunt-tcc-prompt-attribution` | TCC prompts naming the wrong responsible app |
| `hunt-iokit-userclient` | IOKit user-client selector / scalar / struct surface |
| `hunt-private-framework-hijack` | Attacker-influenced `dlopen` and `NSClassFromString` paths |
| `hunt-url-scheme-hijack` | Custom URL scheme dispatchers trusting URL parameters |
| `hunt-mig-subsystem` | MIG-derived Mach-trap kernel surface |
| `hunt-keychain-access-group` | Confused-deputy bugs across keychain access groups |

## Vocabulary

A few terms I made up that show up across the docs:

- **Keep** — the whole studio (workstation, lab host, skills, scripts, project state).
- **Watch** — the static-analysis decision layer. Reads intake and picks the next move.
- **Maproom** — the recipe registry at [`docs/playbooks/investigation-recipes.md`](docs/playbooks/investigation-recipes.md).
- **Gatehouse** — the Ghidra-anchor → lldb-stop handoff.
- **Scriptorium** — the evidence ledger. Every claim points at a hash, a file, and a transcript.

A few macOS terms a newcomer will trip on:

- **MachService** — a launchd-registered name a process can connect to over Mach IPC. The "wrong door" bug class is a daemon listening on a MachService and trusting the wrong client.
- **Audit token** — kernel-vouched identity of a process, retrieved via `xpc_connection_get_audit_token`. Pids are not. Pid-only attribution is the bug.
- **Entitlement** — a key/value claim baked into the code signature. Daemons grant or deny capabilities based on entitlements rather than pids.
- **PrivateFramework** — Apple frameworks under `/System/Library/PrivateFrameworks/`, shipped in the dyld shared cache. Not part of the public SDK.
- **TCC** — Transparency, Consent, and Control. The prompt + database that gates Documents, Camera, FDA, Apple Events, Accessibility.

## Requirements

Workstation: macOS, `bash`, `python3`, `git`, `ssh`, `rsync`, `unzip`, an agent client (Cursor or Claude Code), an SSH alias for the lab host.

Lab host: a Mac (Apple Silicon for the default automated install path), SSH enabled, a user account that can install tools under its own home, `/opt/homebrew/bin/python3` or another 3.10+ via `--remote-python`. The default installer doesn't need admin rights; everything goes under the lab user's home.

## Install

From a clean checkout on the workstation:

```bash
git clone https://github.com/UnsaltedHash42/mac-reversing-station ~/tools/skillz
cd ~/tools/skillz
scripts/setup-keep.sh --host <lab-host> --remote-home /Users/<remote-user>
```

If this is the first time connecting to the lab host and password SSH is still needed for key setup:

```bash
scripts/setup-keep.sh \
  --host <lab-host> \
  --remote-home /Users/<remote-user> \
  --vm-password '<initial-password>'
```

What it does:

1. Links station skills into your agent's skills directory.
2. Creates `~/.ssh/id_ed25519` if missing and installs the public key on the lab host.
3. Verifies non-interactive SSH.
4. Installs Ghidra, Java, `ghidra-mcp`, and the station's Ghidra scripts on the lab host.
5. Deploys `macre-vm-mcp` on the lab host.
6. Writes MCP config for Cursor (`~/.cursor/mcp.json`) and Claude Code (`~/.claude/settings.json`).
7. Runs structural station checks.

Restart your agent client after the installer finishes.

### Cursor vs Claude Code

The installer writes config for both by default. Use `--cursor-only` or `--claude-code-only` if you only want one.

| | Cursor | Claude Code |
|---|--------|-------------|
| MCP config | `~/.cursor/mcp.json` | `~/.claude/settings.json` |
| Skills | `~/.cursor/skills/` | `~/.claude/skills/` |
| Linker script | `cursor/skill-link.sh` | `scripts/skill-link-claude-code.sh` |
| Config writer | `scripts/configure-cursor-mcp.py` | `scripts/configure-claude-code-mcp.py` |

To preview Claude Code MCP config without writing:

```bash
python3 scripts/configure-claude-code-mcp.py --host <lab-host> --remote-home /Users/<remote-user> --dry-run
```

### Rerun safety

The setup scripts are idempotent. Rerunning `setup-keep.sh` for a new lab host updates the `ghidra-mcp` and `macre-vm-mcp` entries to the new host and home; other MCP servers in your config are left alone. To preview without writing:

```bash
python3 scripts/configure-cursor-mcp.py --host <lab-host> --remote-home /Users/<remote-user> --dry-run
python3 scripts/configure-claude-code-mcp.py --host <lab-host> --remote-home /Users/<remote-user> --dry-run
```

### Installer options

```bash
scripts/setup-keep.sh --help
```

Common combinations:

```bash
# Local skills + MCP config only; skip remote installs.
scripts/setup-keep.sh --host <lab-host> --remote-home /Users/<remote-user> \
  --skip-ssh-key --skip-ghidra --skip-dynamic

# Remote tooling but don't touch agent MCP config.
scripts/setup-keep.sh --host <lab-host> --remote-home /Users/<remote-user> --skip-mcp-config

# Claude Code only (skip Cursor config).
scripts/setup-keep.sh --host <lab-host> --remote-home /Users/<remote-user> --claude-code-only

# Different Python on the lab host.
scripts/setup-keep.sh --host <lab-host> --remote-home /Users/<remote-user> \
  --remote-python /usr/bin/python3

# Run live Ghidra checks after install.
scripts/setup-keep.sh --host <lab-host> --remote-home /Users/<remote-user> --live-smoke
```

### Manual install

For when you want each step yourself.

1. Add an SSH alias:

```sshconfig
Host <lab-host>
  HostName <ip-or-dns-name>
  User <remote-user>
  PubkeyAuthentication yes
  ServerAliveInterval 30
```

2. Link skills:

```bash
./cursor/skill-link.sh                # Cursor
./scripts/skill-link-claude-code.sh   # Claude Code
```

3. SSH key access:

```bash
ssh-keygen -t ed25519 -N '' -f "$HOME/.ssh/id_ed25519"
MACRE_MACHINE="<lab-host>" bash scripts/install-vm-ssh-key.sh
ssh -o BatchMode=yes <lab-host> true
```

4. Ghidra and `ghidra-mcp` on the lab host:

```bash
MACRE_MACHINE="<lab-host>" \
MACRE_REMOTE_HOME="/Users/<remote-user>" \
bash scripts/install-ghidra-host.sh --install
```

5. `macre-vm-mcp` on the lab host:

```bash
MACRE_MACHINE="<lab-host>" \
MACRE_REMOTE_HOME="/Users/<remote-user>" \
MACRE_REMOTE_PYTHON="/opt/homebrew/bin/python3" \
bash scripts/deploy-macre-vm-mcp.sh
```

6. Write MCP config:

```bash
python3 scripts/configure-cursor-mcp.py --host <lab-host> --remote-home /Users/<remote-user>
python3 scripts/configure-claude-code-mcp.py --host <lab-host> --remote-home /Users/<remote-user>
```

7. Restart the agent.

## Verifying the install

```bash
bash scripts/smoke-wave3.sh
```

That's structural; doesn't need the lab host. With `--live` it actually drives `ghidra-mcp` against `/bin/ls` on the lab host:

```bash
MACRE_MACHINE="<lab-host>" bash scripts/smoke-wave3.sh --live
```

A healthy install: both MCP servers appear in your agent after restart, structural smoke is zero failures, the live smoke can open / list / decompile / run a script against `/bin/ls`.

## Starting a project

Each target lives in its own clone.

```bash
mkdir -p ~/re && cd ~/re
git clone https://github.com/UnsaltedHash42/mac-reversing-station <project-name>
cd <project-name>
scripts/init-project.sh --name <project-name>
```

If the project has a private remote, pass `--remote <url>` and the initializer rewires git origin.

After init, fill in:

- `LAB_SAFETY.md` — lab host, test user, SIP state, snapshots, allowed dynamic tests.
- `machines.md` — your actual lab aliases.
- `HANDOFF.md` — current objective.

Don't start dynamic testing until `LAB_SAFETY.md` names the host, user, rollback state, and allowed test shape. The agent reads this file every session.

## The pass workflow

Numbered against the artifacts each step produces.

1. **Intake.** "start a pass on `<path>`. PASS-NNN." → `bundle-intake` runs → dossier and target map under `findings/analysis/`, CORPUS updated.
2. **Sync to lab host.** `scripts/rsync-to-vm.sh` records the lab-host path mapping if Ghidra needs the binary there.
3. **Watch.** "what should we look at next" → recommendation: one recipe and one stop condition.
4. **Recipe.** Agent runs scan scripts via `ghidra-mcp` against the recorded lab path. TSVs land in `findings/analysis/`.
5. **Triage.** `scripts/triage.py create` per tier-A anchor. Status starts at `scan-hit`.
6. **Confirm.** Tier-A anchor + `LAB_SAFETY.md` permission → `gatehouse-ghidra-lldb` → `lldb_run_anchors` → transcript under `artifacts/`. Hash-pin via `triage.py transition --binary-sha256`.
7. **Record.** Conclusions land in `SCRIPTORIUM.md`, `CHRONICLE.md`, `HANDOFF.md`. `METRICS.md` counts closures.
8. **Repeat or chain.** Two confirmed primitives → `chain-discovery`. One confirmed primitive worth a PoC → `poc-authoring`.

## Common prompts

The agent picks skills from descriptions. You don't need to name them.

```
start a pass on /Applications/<App Name>.app. PASS-001.
inventory the helpers and XPC services in this bundle.
run the map-xpc-endpoints recipe for PASS-001.
read the decompilation for C-003 and tell me whether the audit token is checked.
confirm the C-003 anchor in lldb. read-only attach, no state changes.
close C-003 with rationale based on the decompilation and the lldb transcript.
suggest the next three highest-value moves.
```

## Triage states

Every candidate ends as one of these. There is no `interesting`.

`hypothesis`, `scan-hit`, `hold`, `blocked`, `escalated`, `reproducing`, `confirmed`, `report-ready`, `reported`, `closed`. Closures with rationale count toward `METRICS.md`.

`scripts/triage.py` enforces the state machine. Illegal transitions are rejected. `closed` requires `--reason`.

## Tools

- **Cursor / Claude Code** — orchestration, reasoning, MCP routing.
- **`ghidra-mcp`** — open Mach-O files, list functions, decompile, run station scripts.
- **`macre-vm-mcp`** — codesign, entitlements, launchd, logs, lldb, dtrace, OS-build snapshots, `procinfo`, `hash_target`.
- **Ghidra GUI** — manual second-pass review when the headless tools aren't enough.

## Troubleshooting

### Agent doesn't show MCP tools

```bash
# Cursor:
python3 -m json.tool ~/.cursor/mcp.json >/dev/null
python3 scripts/configure-cursor-mcp.py --host <lab-host> --remote-home /Users/<remote-user>

# Claude Code:
python3 -m json.tool ~/.claude/settings.json >/dev/null
python3 scripts/configure-claude-code-mcp.py --host <lab-host> --remote-home /Users/<remote-user>
```

Restart the agent. Verify the remote commands work:

```bash
ssh <lab-host> /Users/<remote-user>/bin/ghidra-mcp-launch --version
ssh <lab-host> /Users/<remote-user>/.venvs/macre-vm-mcp/bin/python -c \
  'from macre_vm_mcp.server import build_server; build_server()'
```

### SSH fails

```bash
ssh -v <lab-host> true
MACRE_MACHINE="<lab-host>" bash scripts/install-vm-ssh-key.sh
ssh -o BatchMode=yes <lab-host> true
```

### Ghidra install fails

The installer is idempotent and uses cached downloads. Rerun:

```bash
MACRE_MACHINE="<lab-host>" MACRE_REMOTE_HOME="/Users/<remote-user>" \
  bash scripts/install-ghidra-host.sh --install
MACRE_MACHINE="<lab-host>" MACRE_REMOTE_HOME="/Users/<remote-user>" \
  bash scripts/install-ghidra-host.sh --smoke
```

### Ghidra script not found on the lab host

```bash
MACRE_MACHINE="<lab-host>" MACRE_REMOTE_HOME="/Users/<remote-user>" \
  bash scripts/install-ghidra-host.sh --install
ssh <lab-host> 'ls ~/ghidra-scripts'
```

### `macre-vm-mcp` fails

```bash
MACRE_MACHINE="<lab-host>" MACRE_REMOTE_HOME="/Users/<remote-user>" \
  MACRE_REMOTE_PYTHON="/opt/homebrew/bin/python3" \
  bash scripts/deploy-macre-vm-mcp.sh
```

### Target sync fails

```bash
ssh -o BatchMode=yes <lab-host> true
mkdir -p targets
MACRE_MACHINE="<lab-host>" MACRE_REMOTE_TARGETS="/Users/<remote-user>/Targets" \
  bash scripts/rsync-to-vm.sh --record <target-id> targets/
```

If `targets/` is empty, run intake first.

### Dynamic probe feels risky

Reread `LAB_SAFETY.md`. Move to a crash-test host, snapshot, and ask the agent to write a confirmation plan before running anything that changes state.

## Good output

A productive session leaves:

- A target in `CORPUS.md` with surfaces and family labels.
- Dossier and target map under `findings/analysis/`.
- Tiered anchor TSVs from each scan.
- Candidate JSON under `findings/candidates/`, each with a defensible state.
- lldb transcripts under `artifacts/` for confirmed dynamic checks.
- Scriptorium anchors hash-pinned to the slice they refer to.
- `HANDOFF.md` that lets the next session resume cold.
- A submission packet when a bug is real.

## What stays out of this template

It's a public template. Don't push:

- target binaries
- private PoCs, chain code, exploit primitives
- crash logs, screenshots, scope-sensitive records
- customer data, client artifacts
- secrets, signing material

That work lives in your private project clone.

## Operating boundary

Authorized RE, lab reproduction, RCA, defensive validation, remediation guidance, reporting. PoC code and chain artifacts go in private project clones. Persistence, evasion, C2, deployment tradecraft, and live-target operations are out of scope.

## Future direction

iOS reversing support after the macOS workflow is solid. iOS targets are out of scope until that lane lands.
