# macOS Reversing Station

This repository is a Cursor-driven macOS reverse-engineering station. Clone it when you want to start a new authorized reversing or vulnerability-research project, then let Cursor, Ghidra, and your lab Mac work together from one project folder.

The goal is not to replace the human reverser. The goal is to make the human faster: the keep performs repeatable static analysis, turns results into decision support, drives Ghidra and lab commands, proposes next hypotheses, and updates the project record while you decide what matters.

## Operating Model

The station has three parts:

- **Project clone:** the folder you open in Cursor for one target, program, or assessment. It contains the README, skills, scripts, target inventory, notes, scan outputs, and report drafts.
- **Cursor cockpit:** the IDE and agent session. You ask for sweeps, decompilation, triage, dynamic checks, and writeups from the project clone.
- **Lab host:** a macOS machine or VM reachable by SSH. It runs Ghidra headless, `ghidra-mcp`, `macre-vm-mcp`, LLDB, DTrace, and target binaries when dynamic testing is needed.

Your lab host can be named anything. In this repo, examples use `<lab-host>` and `<remote-user>`. If your SSH alias is `my-lab`, then `<lab-host>` is `my-lab`. If your remote username is `reuser`, then `<remote-user>` is `reuser`.

## Repository Contents

- `Skills/` contains Cursor skills for macOS RE, Ghidra tooling, target-family playbooks, reporting, and lab discipline.
- `docs/ontology/` defines macOS vulnerability classes and the evidence expected for each class.
- `docs/playbooks/` gives starting workflows for privileged helpers/updaters, enterprise agents, developer tools, and TCC-heavy apps.
- `ghidra-scripts/` contains read-only Ghidra postScripts that produce TSV triage output.
- `macre-vm-mcp/` contains VM-side dynamic tooling for LLDB, DTrace, codesign, launchd, logs, and system checks.
- `templates/findings-repo/` contains local project files such as `LAB_SAFETY.md`, `CORPUS.md`, `SCRIPTORIUM.md`, `CHRONICLE.md`, `INDEX.md`, `METRICS.md`, and `REPORTING.md`.
- `scripts/` contains setup, sync, and smoke-test helpers.

## Keep Vocabulary

- **Keep** is the whole project environment: Cursor, project clone, lab host, skills, scripts, and durable project state.
- **Watch** is the static-analysis decision layer. It reads intake and first-pass facts, writes a dossier, names coverage gaps, and recommends recipes or Ghidra sweeps.
- **Maproom** is the investigation recipe registry in `docs/playbooks/investigation-recipes.md`.
- **Scriptorium** is the continuity layer: `SCRIPTORIUM.md`, `CHRONICLE.md`, and linked evidence paths.
- **Gatehouse** is the Ghidra-to-LLDB workflow for carrying static anchors into dynamic confirmation.

Do not push target apps, private PoCs, logs, screenshots, crash reports, scope-sensitive records, customer data, or client artifacts back to a public template repo. Keep that work in your private project clone.

## Requirements

You need two machines or roles:

- **Workstation:** the Mac where you run Cursor and keep project clones.
- **Lab host:** a macOS machine or VM reachable by SSH. It runs Ghidra, `ghidra-mcp`, `macre-vm-mcp`, LLDB, DTrace, and target binaries when dynamic testing is allowed.

Workstation requirements:

- macOS with `bash`, `python3`, `git`, `ssh`, `rsync`, and `unzip`.
- Cursor installed.
- An SSH alias for the lab host in `~/.ssh/config`.

Lab-host requirements:

- macOS on Apple Silicon for the default automated install path.
- SSH enabled.
- A user account that can install tools under its own home directory.
- `/opt/homebrew/bin/python3` for `macre-vm-mcp`, or another Python 3.10+ path passed with `--remote-python`.

The default installer does not require admin install paths. It places lab tools under the remote user's home directory.

## Install

### Fast Path

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

1. Links the station skills into `~/.cursor/skills/`.
2. Creates `~/.ssh/id_ed25519` if missing.
3. Installs your public key on the lab host unless `--skip-ssh-key` is used.
4. Verifies non-interactive SSH.
5. Installs Ghidra, Java, Ghidra MCP, and Ghidra hunt scripts on the lab host.
6. Deploys `macre-vm-mcp` on the lab host.
7. Writes or updates `~/.cursor/mcp.json` with `ghidra-mcp` and `macre-vm-mcp` entries.
8. Runs structural station checks.

Restart Cursor after the installer writes MCP config.

### Rerun Safety

The setup scripts are designed to be safe to rerun on the same workstation:

- `scripts/setup-keep.sh` relinks skills idempotently and reuses an existing SSH key.
- If `~/.ssh/id_ed25519` exists but the `.pub` file is missing, the installer regenerates only the public key.
- `scripts/install-vm-ssh-key.sh` exits early when key auth already works and does not duplicate authorized-key rows.
- `scripts/install-ghidra-host.sh` and `scripts/deploy-macre-vm-mcp.sh` are idempotent remote installs.
- `scripts/configure-cursor-mcp.py` preserves unrelated MCP servers and writes a `.bak` before changing an existing `~/.cursor/mcp.json`.
- Running setup for a new VM intentionally updates the `ghidra-mcp` and `macre-vm-mcp` entries to the new `--host` and `--remote-home`. Other MCP entries are preserved.

To preview Cursor MCP changes without writing:

```bash
python3 scripts/configure-cursor-mcp.py --host <lab-host> --remote-home /Users/<remote-user> --dry-run
```

### Installer Options

```bash
scripts/setup-keep.sh --help
```

Common options:

```bash
# Configure only local Cursor skills and MCP JSON; skip remote installs.
scripts/setup-keep.sh --host <lab-host> --remote-home /Users/<remote-user> --skip-ssh-key --skip-ghidra --skip-dynamic

# Install remote tooling but do not touch Cursor MCP config.
scripts/setup-keep.sh --host <lab-host> --remote-home /Users/<remote-user> --skip-mcp-config

# Use a different Python on the lab host.
scripts/setup-keep.sh --host <lab-host> --remote-home /Users/<remote-user> --remote-python /usr/bin/python3

# Include live Ghidra smoke checks after install.
scripts/setup-keep.sh --host <lab-host> --remote-home /Users/<remote-user> --live-smoke
```

### Manual Install

Use this if you want to run each step yourself or debug setup one layer at a time.

1. Add an SSH alias:

```sshconfig
Host <lab-host>
  HostName <ip-or-dns-name>
  User <remote-user>
  PubkeyAuthentication yes
  ServerAliveInterval 30
```

2. Link Cursor skills:

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

7. Restart Cursor.

## Verify Installation

Run structural checks first:

```bash
bash scripts/smoke-wave3.sh
```

Run live lab-host checks when SSH and remote tooling should be ready:

```bash
MACRE_MACHINE="<lab-host>" bash scripts/smoke-wave3.sh --live
```

Check individual layers:

```bash
ssh -o BatchMode=yes <lab-host> true
MACRE_MACHINE="<lab-host>" MACRE_REMOTE_HOME="/Users/<remote-user>" bash scripts/install-ghidra-host.sh --check
MACRE_MACHINE="<lab-host>" MACRE_REMOTE_HOME="/Users/<remote-user>" bash scripts/install-ghidra-host.sh --smoke
python3 -m json.tool ~/.cursor/mcp.json >/dev/null
```

Expected result after a healthy install:

- `ghidra-mcp` appears in Cursor's MCP tools after restart.
- `macre-vm-mcp` appears in Cursor's MCP tools after restart.
- `scripts/smoke-wave3.sh` reports zero failures.
- `scripts/smoke-wave3.sh --live` can open, list, decompile, and run a Ghidra script against `/bin/ls` on the lab host.

## Start A New Project

Each target, customer program, or research thread should live in its own project clone.

```bash
mkdir -p ~/re
cd ~/re
git clone https://github.com/UnsaltedHash42/mac-reversing-station <project-name>
cd <project-name>
scripts/init-project.sh --name <project-name>
```

If the project has a private Git remote:

```bash
scripts/init-project.sh --name <project-name> --remote <your-private-repo-url>
```

The project initializer copies the findings template without overwriting existing files, creates `HANDOFF.md` and `machines.md`, ensures local work directories exist, and runs the findings template smoke test.

After initialization, fill in:

- `LAB_SAFETY.md`: lab host, test user, SIP state, snapshots, and allowed dynamic test shapes.
- `machines.md`: replace placeholders with your actual lab aliases.
- `HANDOFF.md`: current objective and next artifact.

Authorization is an operator precondition. Do not start dynamic testing until `LAB_SAFETY.md` names the host, user, rollback state, and allowed test shape.

## Target Intake

The preferred start path is to point intake at the original target path:

```bash
python3 scripts/start-target.py "/Applications/<App Name>.app" --pass-id PASS-001
```

For source-available targets:

```bash
python3 scripts/start-target.py "/Applications/<App Name>.app" \
  --pass-id PASS-001 \
  --source-root ../source-checkout \
  --source-ref <commit-or-tag> \
  --source-url <repo-or-release-url>
```

Intake copies the target under `targets/`, writes a target map and dossier under `findings/analysis/`, updates `CORPUS.md`, and seeds Watch decision support plus Scriptorium anchors.

Use manual copy only when you need it:

```bash
mkdir -p targets
cp -R "/Applications/<App Name>.app" targets/
```

## Sync Targets To The Lab Host

Ghidra and dynamic tools run on the lab host, so sync target binaries when a pass needs them there:

```bash
MACRE_MACHINE="<lab-host>" \
MACRE_REMOTE_TARGETS="/Users/<remote-user>/Targets" \
MACRE_PROJECT="<project-name>" \
bash scripts/rsync-to-vm.sh --record <target-id> targets/
```

The sync script records the local-to-remote path mapping in `CORPUS.md` under `Lab Host Path Mapping`. Use that recorded path in Ghidra and Gatehouse prompts.

## Usage

### Normal Loop

1. Start from a target path with `scripts/start-target.py`.
2. Read the dossier and Watch recommendation in `CORPUS.md`.
3. Pick the recommended Maproom recipe from `docs/playbooks/investigation-recipes.md`.
4. Run the first static sweep through `ghidra-mcp`.
5. Save TSVs and notes under `findings/analysis/`.
6. Add candidates or closures to `INDEX.md` and `METRICS.md`.
7. Use Gatehouse LLDB confirmation only after static analysis gives a concrete anchor and `LAB_SAFETY.md` permits dynamic work.
8. Record evidence and decisions in `SCRIPTORIUM.md`, `CHRONICLE.md`, and `HANDOFF.md`.

### First Cursor Prompt

Use this from inside a project clone:

```text
We are in REPO_MODE=analysis in a macOS reversing project.

I am the human operator. Guide me step by step. Tell me what to open, what to run, where the binary should live, and what evidence to save.

First read README.md, LAB_SAFETY.md, machines.md, CORPUS.md, METRICS.md, INDEX.md, SCRIPTORIUM.md, CHRONICLE.md, and HANDOFF.md.

Use Skills/offensive-macos-bundle-intake/SKILL.md. Start PASS-001 from "<target path>". Run target intake, write the target map and dossier, update CORPUS.md, let Watch classify observed surfaces into family labels or unknown/mixed, and choose the first Maproom recipe or static sweep. Do not run dynamic tests until LAB_SAFETY.md allows them. Save outputs under findings/analysis/ and update INDEX.md, METRICS.md, SCRIPTORIUM.md, CHRONICLE.md, and HANDOFF.md.
```

### Common Prompts

Inventory a target:

```text
Inventory targets/<App Name>.app for PASS-001. Identify the main executable, embedded helpers, XPC services, LaunchDaemons/LaunchAgents, privileged helper tools, updater components, Electron indicators, entitlements, code-signing flags, and obvious IPC surfaces. Update CORPUS.md, assign family labels or unknown/mixed, write the dossier, and propose the first Maproom recipe or Ghidra sweep.
```

Run a Ghidra sweep:

```text
Use ghidra-mcp to open the main binary for PASS-001 from the lab-host path recorded in CORPUS.md. Run scan_xpc_client_validation.py and scan_privileged_helper_surface.py. Save TSV output under findings/analysis/ and summarize candidate rows into INDEX.md.
```

Confirm a static anchor with LLDB:

```text
Use Skills/offensive-macos-gatehouse-ghidra-lldb/SKILL.md. Confirm the Ghidra anchor for IDX-001 with LLDB only if LAB_SAFETY.md permits the test shape. Record slide/slice uncertainty, save the LLDB transcript, and link the result in SCRIPTORIUM.md and HANDOFF.md.
```

Ask for next moves:

```text
Based on the current files and candidates, suggest the next three highest-value reversing moves. For each move, explain the expected evidence, the tool you would use, the file you would update, and what would make us stop or continue.
```

Prepare dynamic work safely:

```text
Prepare a safe dynamic confirmation plan for IDX-001. Read LAB_SAFETY.md first. List the exact host, user, command, expected output, rollback/cleanup, and artifact path. Ask for confirmation before running anything that changes system state.
```

## Tool Guide

- **Cursor**: orchestration, notes, promptable reasoning, triage, and file updates.
- **Watch**: intake-driven static decision support and coverage gaps.
- **Maproom**: reusable recipes for common investigation goals.
- **Ghidra MCP**: opening Mach-O files, listing functions, decompiling, running station Ghidra scripts, and producing TSV output.
- **Ghidra GUI**: visual navigation, graphs, and manual second-pass review.
- **macre-vm-mcp**: codesign, entitlements, launchd, logs, LLDB, DTrace, and host checks.
- **Gatehouse**: static-to-dynamic confirmation from Ghidra anchors into LLDB.
- **Scriptorium**: evidence continuity across sessions.
- **Terminal**: setup, sync, git, hashes, and one-off file organization.

## Triage States

Every candidate should become one of:

- `escalated`: likely crosses a trust boundary and deserves deeper RE.
- `hold`: plausible but blocked by setup, missing symbols, or unclear reachability.
- `closed`: expected behavior or correctly gated, with evidence.
- `blocked`: cannot continue until a machine, target, authorization, or tool issue is fixed.
- `reported`: confirmed and packaged.

Do not leave rows as `interesting`. Interesting is a feeling, not a research state.

## Troubleshooting

### Cursor Does Not Show MCP Tools

1. Confirm `~/.cursor/mcp.json` is valid:

```bash
python3 -m json.tool ~/.cursor/mcp.json >/dev/null
```

2. Re-run the config writer:

```bash
python3 scripts/configure-cursor-mcp.py --host <lab-host> --remote-home /Users/<remote-user>
```

3. Fully restart Cursor.

4. Verify the remote commands work:

```bash
ssh <lab-host> /Users/<remote-user>/bin/ghidra-mcp-launch --version
ssh <lab-host> /Users/<remote-user>/.venvs/macre-vm-mcp/bin/python -c 'from macre_vm_mcp.server import build_server; build_server()'
```

### SSH Fails

```bash
ssh -v <lab-host> true
MACRE_MACHINE="<lab-host>" bash scripts/install-vm-ssh-key.sh
ssh -o BatchMode=yes <lab-host> true
```

Check `~/.ssh/config` for the right `HostName`, `User`, and `PubkeyAuthentication yes`.

### Ghidra Install Fails

Re-run the installer; it is idempotent and uses cached downloads when checksums match:

```bash
MACRE_MACHINE="<lab-host>" \
MACRE_REMOTE_HOME="/Users/<remote-user>" \
bash scripts/install-ghidra-host.sh --install
```

Then run:

```bash
MACRE_MACHINE="<lab-host>" \
MACRE_REMOTE_HOME="/Users/<remote-user>" \
bash scripts/install-ghidra-host.sh --smoke
```

### Ghidra Script Not Found On Lab Host

```bash
MACRE_MACHINE="<lab-host>" \
MACRE_REMOTE_HOME="/Users/<remote-user>" \
bash scripts/install-ghidra-host.sh --install
ssh <lab-host> 'ls ~/ghidra-scripts'
```

### `macre-vm-mcp` Fails

```bash
MACRE_MACHINE="<lab-host>" \
MACRE_REMOTE_HOME="/Users/<remote-user>" \
MACRE_REMOTE_PYTHON="/opt/homebrew/bin/python3" \
bash scripts/deploy-macre-vm-mcp.sh
```

If the lab host uses a different Python, pass the path with `MACRE_REMOTE_PYTHON` or `scripts/setup-keep.sh --remote-python`.

### Target Sync Fails

```bash
ssh -o BatchMode=yes <lab-host> true
mkdir -p targets
MACRE_MACHINE="<lab-host>" \
MACRE_REMOTE_TARGETS="/Users/<remote-user>/Targets" \
bash scripts/rsync-to-vm.sh --record <target-id> targets/
```

If `targets/` is empty or missing, run target intake first.

### Dynamic Probe Feels Risky

Stop and read `LAB_SAFETY.md`. Move to a crash-test host or disposable user, snapshot first, and ask Cursor to write a confirmation plan before running anything that changes state.

## Good Output

A productive session leaves behind:

- A target recorded in `CORPUS.md`.
- A dossier and target map under `findings/analysis/`.
- A repeatable TSV or decompile note under `findings/analysis/`.
- Candidate or closure rows in `INDEX.md`.
- Metrics updates in `METRICS.md`.
- Evidence and decisions in `SCRIPTORIUM.md` and `CHRONICLE.md`.
- Dynamic artifacts under `artifacts/` when dynamic work was approved.
- A `HANDOFF.md` that lets the next session resume quickly.
- A report packet when the bug is real.

## Operating Boundary

This station is for authorized reverse engineering, lab reproduction, root-cause analysis, defensive validation, remediation guidance, and reporting. It is not for persistence, evasion, command-and-control, deployment tradecraft, or live exploitation workflow.
