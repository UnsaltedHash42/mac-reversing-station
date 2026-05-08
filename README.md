# macOS Reversing Station

An agent-operated reverse-engineering studio for macOS. The workstation drives an LLM agent (Cursor, Claude Code, or any MCP client). The agent drives Ghidra and lldb on a separate lab Mac through two MCP servers. You drop a binary path; the agent does intake, picks a recipe, runs static sweeps, triages candidates, confirms anchors dynamically, and keeps its own evidence ledger. Your job is judgment.

The goal is not to replace the human reverser. The goal is to make the reverser ten times faster on the parts that are repeatable, and to leave a paper trail the next session can resume cold.

This template is for **authorized** reverse engineering: red-team research, vulnerability research, defensive validation, root-cause analysis, reporting. It is not a deployment, persistence, or live-exploitation framework. PoCs and chain artifacts stay in private project clones, not this template.

## The loop

```
                    ┌────────────────────────────────┐
                    │                                │
                    │    intake → watch → recipe     │
                    │      → scan → triage           │
                    │      → confirm → record        │
                    │                                │
                    │   repeat | chain | close       │
                    │                                │
                    └────────────────────────────────┘
```

Every step has an artifact:

| Step | Artifact | Where it lands |
|---|---|---|
| Intake | dossier + target map | `findings/analysis/PASS-*-dossier.json` |
| Watch | next-move recommendation | `CORPUS.md` Watch Decision Support |
| Recipe | named procedure | `docs/playbooks/investigation-recipes.md` |
| Scan | tiered anchor TSV | `findings/analysis/PASS-*.tsv` |
| Triage | candidate state | `findings/candidates/C-*.json` |
| Confirm | lldb transcript + hash | `artifacts/PASS-*.lldb.log` + `SCRIPTORIUM.md` |
| Record | evidence anchor | `SCRIPTORIUM.md`, `CHRONICLE.md`, `HANDOFF.md` |

If a step does not produce an artifact, you skipped it.

## Try it in 30 minutes

[**docs/tutorial/first-pass-tccd.md**](docs/tutorial/first-pass-tccd.md) walks you through one full lap of the loop against `tccd` (the user-side TCC permission broker — on every Mac, real attack surface, not actually exploitable through anything in the tutorial). Start there if this is your first session.

If you want the methodology map without running anything, read [**Skills/README.md**](Skills/README.md).

## Going 0day hunting (skip the rest of this section if you are not)

If you have done macOS RE before, the studio's mental model is:

1. **Pick a target queue.** Privileged helpers and enterprise agents are high-yield. OS-component daemons are second. TCC-heavy consumer apps are third. See [`docs/playbooks/`](docs/playbooks/) for shape-by-shape playbooks.
2. **Run intake on every binary.** Cheap. Surfaces what surfaces are.
3. **Run all relevant scan scripts.** They emit tiered anchors; tier A goes to lldb, tier B back to Ghidra, tier C is a starting point only.
4. **Maintain candidate hygiene.** Every row converges to `closed` (with rationale), `escalated` (deeper RE), or `blocked` (lab/auth issue). No `interesting`.
5. **Chain discovery is its own skill.** Two confirmed primitives → exploitability rating → one next experiment. See `Skills/offensive-macos-chain-discovery/SKILL.md`.
6. **Submission packet before reporting.** See `Skills/offensive-macos-submission-packet/SKILL.md`.

The skills you will reach for repeatedly:

- `bundle-intake` (entry), `watch-static-analysis` (decide), `maproom-recipes` (recipe registry)
- `tooling-ghidra-headless`, `tooling-lldb`, `tooling-dtrace` (drive the tools)
- `gatehouse-ghidra-lldb` (static→dynamic), `scriptorium-evidence` (continuity)
- `chain-discovery`, `poc-authoring`, `submission-packet` (exit)

The hunt skills (`hunt-wrong-door`, `hunt-defaults-bypass`, `hunt-catalyst-porting-gap`) are one bug class each. Read the one that matches the target before the sweep, not after.

## Operating model

The studio has three parts:

- **Project clone:** the folder you open in your agent for one target / program / assessment. Contains `LAB_SAFETY.md`, target inventory, dossiers, scan TSVs, candidate YAML files, lldb transcripts, scriptorium, chronicle.
- **Workstation cockpit:** the IDE and agent session. Cursor or Claude Code; any MCP client works.
- **Lab host:** a macOS machine or VM reachable by SSH. Runs Ghidra headless, `ghidra-mcp`, `macre-vm-mcp`, lldb, dtrace.

The lab host can be named anything. In examples below, `<lab-host>` is your SSH alias and `<remote-user>` is the lab account.

## Vocabulary

Repo-specific terms (see [Skills/README.md](Skills/README.md) for the full skill set):

- **Keep** — the whole studio: workstation + lab host + skills + scripts + project state.
- **Watch** — the static-analysis decision layer. Reads intake, names the next move.
- **Maproom** — the investigation-recipe registry at [`docs/playbooks/investigation-recipes.md`](docs/playbooks/investigation-recipes.md).
- **Gatehouse** — the Ghidra-anchor → lldb-stop handoff.
- **Scriptorium** — the evidence ledger. Every claim points at a hash + file + transcript.

macOS-specific terms a newcomer will trip on:

- **MachService** — a launchd-registered name a process can connect to over Mach IPC. The "wrong door" bug class is about a daemon listening on a MachService and trusting the wrong client.
- **Audit token** — kernel-vouched identity of a process, retrieved via `xpc_connection_get_audit_token`. The right way to identify a peer; checking only the pid is the wrong way.
- **Entitlement** — a key/value claim baked into the code signature. Daemons grant or deny capabilities based on entitlements rather than pids.
- **PrivateFramework** — Apple frameworks under `/System/Library/PrivateFrameworks/` that ship in the dyld shared cache. Not part of the public SDK.
- **TCC** — Transparency, Consent, and Control. The user-prompt + database that gates Documents / Camera / FDA / Apple Events / Accessibility access.

## Requirements

Workstation (your Mac):

- macOS with `bash`, `python3`, `git`, `ssh`, `rsync`, `unzip`.
- An agent client. Cursor or Claude Code both work.
- An SSH alias for the lab host in `~/.ssh/config`.

Lab host (Apple Silicon Mac or VM):

- macOS, SSH enabled.
- A user account that can install tools under its own home.
- `/opt/homebrew/bin/python3` (or any 3.10+ via `--remote-python`).

The default installer does not require admin install paths. Lab tools live under `~/<remote-user>/`.

## Install

### Fast path

From a clean station checkout on the workstation:

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

What the installer does:

1. Links station skills into your agent's skills directory (Cursor: `~/.cursor/skills/`; for Claude Code, see below).
2. Creates `~/.ssh/id_ed25519` if missing.
3. Installs your public key on the lab host unless `--skip-ssh-key` is used.
4. Verifies non-interactive SSH.
5. Installs Ghidra, Java, `ghidra-mcp`, and station Ghidra scripts on the lab host.
6. Deploys `macre-vm-mcp` on the lab host.
7. Writes or updates `~/.cursor/mcp.json` with `ghidra-mcp` and `macre-vm-mcp` entries.
8. Runs structural station checks.

Restart your agent client after the installer writes MCP config.

### Cursor vs. Claude Code

The installer writes Cursor's MCP config by default. For Claude Code, the same MCP servers register through `~/.claude/settings.json` or per-project `.claude/settings.json`. Add an entry like:

```json
{
  "mcpServers": {
    "ghidra-mcp": {
      "command": "ssh",
      "args": ["-o", "BatchMode=yes", "-o", "ServerAliveInterval=30",
               "<lab-host>", "/Users/<remote-user>/bin/ghidra-mcp-launch"]
    },
    "macre-vm-mcp": {
      "command": "ssh",
      "args": ["-o", "BatchMode=yes", "-o", "ServerAliveInterval=30",
               "<lab-host>", "/Users/<remote-user>/.venvs/macre-vm-mcp/bin/python",
               "-m", "macre_vm_mcp"]
    }
  }
}
```

Skills are read from `~/.claude/skills/` (or per-project `.claude/skills/`). The `cursor/skill-link.sh` script links into `~/.cursor/skills/`; symlink the same `Skills/*` directories into your Claude Code skills path or copy them.

### Rerun safety

The setup scripts are idempotent:

- `scripts/setup-keep.sh` relinks skills idempotently and reuses an existing SSH key.
- If `~/.ssh/id_ed25519` exists but the `.pub` file is missing, only the public key is regenerated.
- `scripts/install-vm-ssh-key.sh` exits early when key auth already works; no duplicate authorized-key rows.
- `scripts/install-ghidra-host.sh` and `scripts/deploy-macre-vm-mcp.sh` are idempotent remote installs.
- `scripts/configure-cursor-mcp.py` preserves unrelated MCP servers and writes a `.bak` before changing an existing `~/.cursor/mcp.json`.
- Setup for a new lab host updates the `ghidra-mcp` and `macre-vm-mcp` entries to the new `--host` and `--remote-home`. Other MCP entries are preserved.

To preview Cursor MCP changes without writing:

```bash
python3 scripts/configure-cursor-mcp.py --host <lab-host> --remote-home /Users/<remote-user> --dry-run
```

### Installer options

```bash
scripts/setup-keep.sh --help
```

Common combinations:

```bash
# Configure only local skills + MCP JSON; skip remote installs.
scripts/setup-keep.sh --host <lab-host> --remote-home /Users/<remote-user> \
  --skip-ssh-key --skip-ghidra --skip-dynamic

# Install remote tooling but do not touch agent MCP config.
scripts/setup-keep.sh --host <lab-host> --remote-home /Users/<remote-user> --skip-mcp-config

# Use a different Python on the lab host.
scripts/setup-keep.sh --host <lab-host> --remote-home /Users/<remote-user> \
  --remote-python /usr/bin/python3

# Include live Ghidra smoke checks after install.
scripts/setup-keep.sh --host <lab-host> --remote-home /Users/<remote-user> --live-smoke
```

### Manual install

Use this to run each step yourself or debug setup one layer at a time.

1. Add an SSH alias:

```sshconfig
Host <lab-host>
  HostName <ip-or-dns-name>
  User <remote-user>
  PubkeyAuthentication yes
  ServerAliveInterval 30
```

2. Link skills (Cursor):

```bash
./cursor/skill-link.sh
```

3. Install SSH key access:

```bash
ssh-keygen -t ed25519 -N '' -f "$HOME/.ssh/id_ed25519"
MACRE_MACHINE="<lab-host>" bash scripts/install-vm-ssh-key.sh
ssh -o BatchMode=yes <lab-host> true
```

4. Install Ghidra and `ghidra-mcp` on the lab host:

```bash
MACRE_MACHINE="<lab-host>" \
MACRE_REMOTE_HOME="/Users/<remote-user>" \
bash scripts/install-ghidra-host.sh --install
```

5. Deploy `macre-vm-mcp` on the lab host:

```bash
MACRE_MACHINE="<lab-host>" \
MACRE_REMOTE_HOME="/Users/<remote-user>" \
MACRE_REMOTE_PYTHON="/opt/homebrew/bin/python3" \
bash scripts/deploy-macre-vm-mcp.sh
```

6. Write Cursor MCP config:

```bash
python3 scripts/configure-cursor-mcp.py --host <lab-host> --remote-home /Users/<remote-user>
```

7. Restart your agent.

## Verify installation

Structural checks (no lab host required):

```bash
bash scripts/smoke-wave3.sh
```

Live lab-host checks (SSH and remote tooling should be ready):

```bash
MACRE_MACHINE="<lab-host>" bash scripts/smoke-wave3.sh --live
```

Per-layer:

```bash
ssh -o BatchMode=yes <lab-host> true
MACRE_MACHINE="<lab-host>" MACRE_REMOTE_HOME="/Users/<remote-user>" bash scripts/install-ghidra-host.sh --check
MACRE_MACHINE="<lab-host>" MACRE_REMOTE_HOME="/Users/<remote-user>" bash scripts/install-ghidra-host.sh --smoke
python3 -m json.tool ~/.cursor/mcp.json >/dev/null
```

Healthy install:

- `ghidra-mcp` and `macre-vm-mcp` appear in your agent's MCP tools list after restart.
- `scripts/smoke-wave3.sh` reports zero failures.
- `scripts/smoke-wave3.sh --live` opens, lists, decompiles, and runs a Ghidra script against `/bin/ls` on the lab host.

## Start a new project

Each target / program / research thread should live in its own project clone.

```bash
mkdir -p ~/re
cd ~/re
git clone https://github.com/UnsaltedHash42/mac-reversing-station <project-name>
cd <project-name>
scripts/init-project.sh --name <project-name>
```

If the project has a private git remote:

```bash
scripts/init-project.sh --name <project-name> --remote <your-private-repo-url>
```

The project initializer copies the findings template without overwriting existing files, creates `HANDOFF.md` and `machines.md`, ensures local work directories exist, and runs the findings-template smoke test.

After initialization, fill in:

- `LAB_SAFETY.md` — lab host, test user, SIP state, snapshots, allowed dynamic test shapes.
- `machines.md` — replace placeholders with your actual lab aliases.
- `HANDOFF.md` — current objective and next artifact.

**Authorization is an operator precondition.** Do not start dynamic testing until `LAB_SAFETY.md` names the host, user, rollback state, and allowed test shape.

## Per-pass workflow

The agent will run this loop for you. The numbered steps are what you will see happen.

1. **Intake.** Type "start a pass on `<path>`. PASS-NNN." → `bundle-intake` fires → `scripts/start-target.py` produces dossier + target map under `findings/analysis/`, updates `CORPUS.md`.
2. **Sync to lab host.** If Ghidra needs the binary, `scripts/rsync-to-vm.sh` records the `Lab Host Path Mapping` row.
3. **Watch.** Type "what should we look at next" → `watch-static-analysis` reads CORPUS, picks one Maproom recipe, names the next artifact and the stop condition.
4. **Recipe.** The agent runs the recipe via `ghidra-mcp` against the recorded lab path. Scan scripts emit tiered anchor TSVs to `findings/analysis/`.
5. **Triage.** The agent creates a candidate file per tier-A anchor at `findings/candidates/C-NNN.json` via `scripts/triage.py create`. Status starts at `scan-hit`; transitions go through `scripts/triage.py transition`. The CLI rejects illegal transitions and requires `--reason` for `closed`.
6. **Confirm.** Tier-A anchor + `LAB_SAFETY.md` permission → `gatehouse-ghidra-lldb` → `lldb_run_anchors` → transcript under `artifacts/`. Hash-pin the binary slice.
7. **Record.** Every conclusion lands in `SCRIPTORIUM.md` (anchor) + `CHRONICLE.md` (timeline) + `HANDOFF.md` (next move). `METRICS.md` counts closures and escalations.
8. **Repeat or chain.** When two confirmed primitives could combine, `chain-discovery` fires and produces an Exploitability And Chainability row. When a single confirmed primitive justifies a PoC, `poc-authoring` takes over.

## Common operator prompts

Each prompt below auto-invokes the right skill. You do not need to name skills.

```
start a pass on /Applications/<App Name>.app. PASS-001.
```

```
inventory the helpers and XPC services in this bundle.
```

```
run the map-xpc-endpoints recipe for PASS-001.
```

```
read the decompilation for C-003 and tell me whether the audit token is checked.
```

```
confirm the C-003 anchor in lldb. read-only attach, no state changes.
```

```
close C-003 with rationale based on the decompilation and the lldb transcript.
```

```
suggest the next three highest-value moves and what would make us stop or continue.
```

```
prepare a safe dynamic confirmation plan for C-007. read LAB_SAFETY.md first.
```

## Triage states

Every candidate converges to one of these. No `interesting`.

- `hypothesis` — plausible class match, no evidence yet.
- `scan-hit` — static / metadata sweep produced a candidate row.
- `hold` — worth revisiting, not the current pass priority.
- `blocked` — cannot proceed until a lab / auth / tool issue is fixed.
- `escalated` — promoted to deep dive.
- `reproducing` — active dynamic confirmation or PoC minimization.
- `confirmed` — lab reproduction + root cause understood.
- `report-ready` — evidence package complete; see `REPORTING.md`.
- `reported` — sent to vendor / internal team / Apple.
- `closed` — closed with rationale. Closures are research output and count in `METRICS.md`.

## Tool guide

- **Cursor / Claude Code** — orchestration, reasoning, file updates, MCP routing.
- **`ghidra-mcp`** — opening Mach-O files, listing functions, decompiling, running station Ghidra scripts.
- **`macre-vm-mcp`** — codesign, entitlements, launchd, logs, lldb, dtrace, host checks, OS-build snapshots.
- **Ghidra GUI** — visual navigation, graphs, manual second-pass review. Manual escape hatch.
- **Watch** — intake-driven static decision support.
- **Maproom** — recipe registry.
- **Gatehouse** — static-anchor → lldb-stop handoff.
- **Scriptorium** — evidence ledger.
- **Terminal** — setup, sync, git, hashes, one-off file work.

## Troubleshooting

### Agent does not show MCP tools

```bash
python3 -m json.tool ~/.cursor/mcp.json >/dev/null
python3 scripts/configure-cursor-mcp.py --host <lab-host> --remote-home /Users/<remote-user>
```

Fully restart your agent. Verify the remote commands work:

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

Check `~/.ssh/config` for the right `HostName`, `User`, and `PubkeyAuthentication yes`.

### Ghidra install fails

The installer is idempotent and uses cached downloads when checksums match:

```bash
MACRE_MACHINE="<lab-host>" \
MACRE_REMOTE_HOME="/Users/<remote-user>" \
bash scripts/install-ghidra-host.sh --install

MACRE_MACHINE="<lab-host>" \
MACRE_REMOTE_HOME="/Users/<remote-user>" \
bash scripts/install-ghidra-host.sh --smoke
```

### Ghidra script not found on lab host

```bash
MACRE_MACHINE="<lab-host>" \
MACRE_REMOTE_HOME="/Users/<remote-user>" \
bash scripts/install-ghidra-host.sh --install
ssh <lab-host> 'ls ~/ghidra-scripts'
```

### `macre-vm-mcp` fails

```bash
MACRE_MACHINE="<lab-host>" \
MACRE_REMOTE_HOME="/Users/<remote-user>" \
MACRE_REMOTE_PYTHON="/opt/homebrew/bin/python3" \
bash scripts/deploy-macre-vm-mcp.sh
```

If the lab host uses a different Python, pass `MACRE_REMOTE_PYTHON` or `scripts/setup-keep.sh --remote-python`.

### Target sync fails

```bash
ssh -o BatchMode=yes <lab-host> true
mkdir -p targets
MACRE_MACHINE="<lab-host>" \
MACRE_REMOTE_TARGETS="/Users/<remote-user>/Targets" \
bash scripts/rsync-to-vm.sh --record <target-id> targets/
```

If `targets/` is empty or missing, run intake first.

### Dynamic probe feels risky

Stop and reread `LAB_SAFETY.md`. Move to a crash-test host or disposable user, snapshot first, and ask the agent to write a confirmation plan before running anything that changes state.

## Good output

A productive session leaves behind:

- A target recorded in `CORPUS.md` with surfaces and family labels.
- Dossier and target map under `findings/analysis/`.
- Tiered anchor TSVs from each scan that ran.
- Candidate JSON files under `findings/candidates/`, each with a defensible state.
- lldb transcripts under `artifacts/` for confirmed dynamic checks.
- Scriptorium anchors that hash-pin every claim.
- A `HANDOFF.md` that lets the next session resume cold.
- A submission packet when a bug is real.

## What does not belong in this template

This is a public template repo. Do not push:

- target binaries
- private PoCs, chain code, exploit primitives
- crash logs, screenshots, scope-sensitive records
- customer data, client artifacts
- `.env`, secrets, signing material

That work lives in your private project clone.

## Operating boundary

This studio is for authorized reverse engineering, lab reproduction, root-cause analysis, defensive validation, remediation guidance, and reporting. PoC code and chain artifacts live in private project clones, not this template. Persistence, evasion, command-and-control, deployment tradecraft, and live-target operations are out of scope.

## Future direction

The studio is intended to grow into iOS reversing support after the macOS workflow is solid. Until that lane lands, iOS targets are out of scope.
