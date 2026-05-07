# macOS Reversing Station

This repository is a Cursor-driven macOS reverse-engineering station. Clone it when you want to start a new authorized reversing or vulnerability-research project, then let Cursor, Ghidra, and your lab Mac work together from one project folder.

The goal is not to replace the human reverser. The goal is to make the human faster: the workbench performs repeatable static analysis, turns results into decision support, drives Ghidra and lab commands, proposes next hypotheses, and updates the project record while you decide what matters.

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
- `templates/findings-repo/` contains local project files such as `LAB_SAFETY.md`, `CORPUS.md`, `EVIDENCE_LEDGER.md`, `FLIGHT_RECORDER.md`, `INDEX.md`, `METRICS.md`, and `REPORTING.md`.
- `scripts/` contains setup, sync, and smoke-test helpers.

## Workbench Vocabulary

- **Workbench** is the whole project environment: Cursor, project clone, lab host, skills, scripts, and durable project state.
- **Scryer** is the static-analysis decision layer. It reads intake and first-pass facts, writes a dossier, names coverage gaps, and recommends recipes or Ghidra sweeps.
- **Grimoire** is the investigation recipe registry in `docs/playbooks/investigation-recipes.md`.
- **Ledger** is the continuity layer: `EVIDENCE_LEDGER.md`, `FLIGHT_RECORDER.md`, and linked evidence paths.
- **Bridge** is the Ghidra-to-LLDB workflow for carrying static anchors into dynamic confirmation.

Do not push target apps, private PoCs, logs, screenshots, crash reports, scope-sensitive records, customer data, or client artifacts back to a public template repo. Keep that work in your private project clone.

## One-Time Environment Setup

Do this once per workstation/lab-host pair.

### 1. Pick Local And Remote Names

Choose where station projects live locally:

```bash
export MACRE_PROJECTS_ROOT="$HOME/re"
```

Choose the SSH alias and remote home directory for your lab host:

```bash
export MACRE_MACHINE="<lab-host>"
export MACRE_REMOTE_HOME="/Users/<remote-user>"
export MACRE_REMOTE_TARGETS="$MACRE_REMOTE_HOME/Targets"
export MACRE_REMOTE_PYTHON="/opt/homebrew/bin/python3"
```

Add the SSH alias to `~/.ssh/config`:

```sshconfig
Host <lab-host>
  HostName <ip-or-dns-name>
  User <remote-user>
  PubkeyAuthentication yes
  ServerAliveInterval 30
```

Verify SSH reaches the lab host:

```bash
ssh -o BatchMode=no <lab-host> 'uname -m; sw_vers -productVersion'
```

### 2. Clone The Station Template

Keep one clean local copy for setup and for starting new projects:

```bash
mkdir -p "$HOME/tools"
cd "$HOME/tools"
git clone https://github.com/UnsaltedHash42/mac-reversing-station skillz
cd skillz
```

### 3. Link Cursor Skills

```bash
./cursor/skill-link.sh
```

This makes the station skills available to Cursor. If the skill list looks stale, restart Cursor.

### 4. Install SSH Key Access

Generate a key if you do not already have one:

```bash
ssh-keygen -t ed25519 -N '' -f "$HOME/.ssh/id_ed25519"
```

Install the public key on the lab host:

```bash
MACRE_MACHINE="<lab-host>" bash scripts/install-vm-ssh-key.sh
```

Verify non-interactive SSH:

```bash
ssh -o BatchMode=yes <lab-host> true
```

### 5. Install Ghidra And MCP On The Lab Host

```bash
MACRE_MACHINE="<lab-host>" \
MACRE_REMOTE_HOME="/Users/<remote-user>" \
bash scripts/install-ghidra-host.sh --install
```

Smoke-test the Ghidra side:

```bash
MACRE_MACHINE="<lab-host>" \
MACRE_REMOTE_HOME="/Users/<remote-user>" \
bash scripts/install-ghidra-host.sh --smoke
```

Expected result:

- Java prints.
- Ghidra prints.
- `ghidra-headless-mcp` prints.
- `/bin/ls` opens in a Ghidra project.
- Function listing works.
- Decompilation works.
- One Ghidra hunt script returns TSV.

### 6. Deploy Dynamic Tooling

```bash
MACRE_MACHINE="<lab-host>" \
MACRE_REMOTE_HOME="/Users/<remote-user>" \
MACRE_REMOTE_PYTHON="/opt/homebrew/bin/python3" \
bash scripts/deploy-macre-vm-mcp.sh
```

`macre-vm-mcp` is what Cursor uses for LLDB, DTrace, codesign, entitlement dumps, launchd inspection, and logs.

### 7. Configure Cursor MCP

Open `~/.cursor/mcp.json` and add entries like this, replacing placeholders:

```json
{
  "mcpServers": {
    "ghidra-mcp": {
      "command": "ssh",
      "args": [
        "-o", "BatchMode=yes",
        "-o", "ServerAliveInterval=30",
        "<lab-host>",
        "/Users/<remote-user>/bin/ghidra-mcp-launch"
      ],
      "env": {}
    },
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
  }
}
```

Fully restart Cursor after changing MCP config.

### 8. Validate The Station

From the clean station checkout:

```bash
bash scripts/smoke-wave3.sh
```

Run live checks too:

```bash
MACRE_MACHINE="<lab-host>" bash scripts/smoke-wave3.sh --live
```

The default smoke is structural and portable. The live smoke requires the lab host.

## Starting A New Reversing Project

Do this for every new target, customer program, or research thread.

### 1. Clone A Fresh Project

```bash
mkdir -p "$HOME/re"
cd "$HOME/re"
git clone https://github.com/UnsaltedHash42/mac-reversing-station <project-name>
cd <project-name>
```

If you use a private Git remote for the project, repoint `origin` before pushing:

```bash
git remote set-url origin <your-private-repo-url>
```

### 2. Add Local Findings Files

The station files stay in the clone. The findings template creates the local project files you will actually fill in.

```bash
rsync -a --ignore-existing templates/findings-repo/ ./
cp -n HANDOFF.md.template HANDOFF.md
cp -n machines.md.template machines.md
bash scripts/smoke-findings-repo.sh
```

You should now have:

- `LAB_SAFETY.md` for machine roles, snapshots, test users, and destructive-test rules.
- `CORPUS.md` for apps, binaries, versions, pass IDs, surfaces, and family labels.
- `INDEX.md` for candidate rows and findings.
- `METRICS.md` for candidate funnel and closure tracking.
- `REPORTING.md` and `SUBMISSION_TRIAGE.md` for packaging.
- `HANDOFF.md` for the current session state.
- `targets/` for local copies of binaries being reversed.
- `findings/analysis/` for TSVs, decompile notes, and static-analysis output.
- `artifacts/` for logs, screenshots, crash reports, and dynamic proof.
- `tools/custom/` for target-specific harnesses.

### 3. Open The Project In Cursor

Use **File -> Open Folder...** and choose:

```text
~/re/<project-name>
```

Cursor should be working from the project clone, not from a random downloads folder. This matters because all agent output should land in the project.

### 4. Confirm Safety And Project State

Authorization is a precondition for using the station, not a required file in every project. Before asking Cursor to hunt:

1. Confirm you have authority to analyze the target and understand out-of-scope boundaries.
2. Fill in `LAB_SAFETY.md`: lab host alias, remote user, SIP state, snapshot state, disposable user, and tests allowed on each machine.
3. Fill in `machines.md`: replace `<PrimaryLab>` with your SSH alias.
4. Let the target intake step create or update `CORPUS.md` with `PASS-001`, target inventory, surface notes, and family labels.
5. Fill in `HANDOFF.md`: write the next concrete objective.

Do not start dynamic testing until `LAB_SAFETY.md` says which host/user can safely run the target.

## Where The Binary Lives

Use two locations:

- Local project copy: `targets/`
- Remote lab-host copy: `$MACRE_REMOTE_TARGETS/<project-name>/`

The local `targets/` directory is where copied app bundles or binaries live. It is ignored by git.

The preferred start path is to point the intake script at the original target:

```bash
python3 scripts/start-target.py "/Applications/<App Name>.app" --pass-id PASS-001
```

The script copies the target under `targets/`, writes a target map under `findings/analysis/`, and updates `CORPUS.md` with initial inventory and family labels.

You can still copy targets manually when needed.

For an installed app:

```bash
mkdir -p targets
cp -R "/Applications/<App Name>.app" targets/
```

For a downloaded installer:

```bash
mkdir -p targets
cp "/path/to/<Installer>.pkg" targets/
```

For one binary:

```bash
mkdir -p targets
cp "/path/to/<binary>" targets/
```

Record every target in `CORPUS.md` with:

- app or component name
- version/build
- source URL or acquisition path
- hash if useful
- target family labels inferred from inventory
- pass ID
- scope note if the target needs one

When the target needs Ghidra or dynamic tooling on the lab host, sync it:

```bash
MACRE_MACHINE="<lab-host>" \
MACRE_REMOTE_TARGETS="/Users/<remote-user>/Targets" \
MACRE_PROJECT="<project-name>" \
bash scripts/rsync-to-vm.sh --record <target-id> targets/
```

After sync, the remote path is:

```text
/Users/<remote-user>/Targets/<project-name>/
```

The sync script records this mapping in `CORPUS.md` under `Lab Host Path Mapping`. Use the recorded path in Ghidra prompts instead of retyping it from memory.

## How You Reverse With The Station

You are usually not clicking around in Ghidra first. The normal loop is:

1. Point Cursor or `scripts/start-target.py` at the original target path.
2. Let intake copy the target under `targets/`, write a target map and dossier, and update `CORPUS.md`.
3. Let Scryer classify observed surfaces, name coverage gaps, recommend recipes, and choose family labels or `unknown/mixed`.
4. Ask Cursor to run the recommended Ghidra sweep through `ghidra-mcp`.
5. Triage TSV rows in `findings/analysis/` and link the evidence in the Ledger.
6. Pick one candidate for deeper decompilation or Bridge confirmation.
7. Use `macre-vm-mcp`, LLDB, DTrace, logs, and small harnesses only when static analysis justifies it.
8. Save results to `INDEX.md`, `METRICS.md`, `EVIDENCE_LEDGER.md`, `FLIGHT_RECORDER.md`, `HANDOFF.md`, and `artifacts/`.

You can still open the Ghidra GUI manually on the lab host when visual navigation helps. Cursor should still save durable notes and outputs back into the project clone.

## First Cursor Prompt

Use this from inside the project clone:

```text
We are in REPO_MODE=analysis in a macOS reversing project.

I am the human operator. Guide me step by step. Tell me what to open, what to run, where the binary should live, and what evidence to save.

First read README.md, LAB_SAFETY.md, machines.md, CORPUS.md, METRICS.md, INDEX.md, and HANDOFF.md.

Use Skills/offensive-macos-bundle-intake/SKILL.md. Start PASS-001 from "<target path>". Run target intake, write the target map and dossier, update CORPUS.md, let Scryer classify observed surfaces into family labels or unknown/mixed, and choose the first Grimoire recipe or static sweep. Do not run dynamic tests until LAB_SAFETY.md allows them. Save outputs under findings/analysis/ and update INDEX.md, METRICS.md, EVIDENCE_LEDGER.md, FLIGHT_RECORDER.md, and HANDOFF.md.
```

## Prompt Patterns

### Inventory The Target

```text
Inventory targets/<App Name>.app for PASS-001. Identify the main executable, embedded helpers, XPC services, LaunchDaemons/LaunchAgents, privileged helper tools, updater components, Electron indicators, entitlements, code-signing flags, and obvious IPC surfaces. Update CORPUS.md, assign family labels or unknown/mixed, write the dossier, and propose the first Grimoire recipe or Ghidra sweep.
```

### Run A Ghidra Sweep

```text
Use ghidra-mcp to open the main binary for PASS-001 from the lab-host path recorded in CORPUS.md. Run scan_xpc_client_validation.py and scan_privileged_helper_surface.py. Save TSV output under findings/analysis/ and summarize candidate rows into INDEX.md.
```

### Confirm A Static Anchor With LLDB

```text
Use Skills/offensive-macos-bridge-ghidra-lldb/SKILL.md. Confirm the Ghidra anchor for IDX-001 with LLDB only if LAB_SAFETY.md permits the test shape. Record slide/slice uncertainty, save the LLDB transcript, and link the result in EVIDENCE_LEDGER.md and HANDOFF.md.
```

### Decompile One Candidate

```text
Deep dive candidate IDX-001. Use ghidra-mcp to find the listener/delegate or authorization function, decompile it, trace callers and relevant strings, and write a short hypothesis note under findings/analysis/. Do not attempt a PoC yet.
```

### Ask For On-The-Fly Suggestions

```text
Based on the current files and candidates, suggest the next three highest-value reversing moves. For each move, explain the expected evidence, the command/tool you would use, the file you would update, and what would make us stop or continue.
```

### Prepare A Dynamic Test

```text
Prepare a safe dynamic confirmation plan for IDX-001. Read LAB_SAFETY.md first. List the exact host, user, command, expected output, rollback/cleanup, and artifact path. Ask for confirmation before running anything that changes system state.
```

### Close A False Positive

```text
Close IDX-001 as a false positive if the decompiled authorization path is correct. Write the closure rationale in INDEX.md and update METRICS.md. Include the function, check performed, and evidence path.
```

### Produce A Report Packet

```text
Use Skills/offensive-macos-submission-packet/SKILL.md to draft a vendor-facing report for IDX-003. Keep it analysis-focused: summary, affected versions, preconditions, root cause, impact, minimal reproduction, evidence, and remediation guidance. Do not include persistence, evasion, or operational chaining.
```

## Which Tools To Use When

- Use **Cursor** for orchestration, notes, promptable reasoning, triage, and writing files.
- Use **Ghidra MCP** for opening Mach-O files, listing functions, decompiling, running station Ghidra scripts, and extracting repeatable TSV output.
- Use **Ghidra GUI** when you want visual navigation, graphs, or a second human view.
- Use **macre-vm-mcp** for codesign, entitlements, launchd, logs, LLDB, DTrace, and host checks.
- Use **Scryer** recommendations and the **Grimoire** recipe registry to decide which static artifact should come next.
- Use **Bridge** only after a static anchor exists and lab safety allows dynamic confirmation.
- Use **Terminal** for simple copy, sync, git, hashes, and one-off file organization.
- Use **custom harnesses** only after a static hypothesis is specific enough to justify them.

## Triage Rules

After a sweep, every candidate should become one of:

- `escalated`: likely crosses a trust boundary and deserves deeper RE.
- `hold`: plausible but blocked by missing setup, missing symbols, or unclear reachability.
- `closed`: expected behavior or correctly gated, with evidence.
- `blocked`: cannot continue until a machine, target, authorization, or tool problem is fixed.
- `reported`: confirmed and packaged.

Do not leave rows as "interesting." Interesting is a feeling, not a research state.

## Daily Workflow

From the project clone:

```bash
bash scripts/smoke-findings-repo.sh
ssh -o BatchMode=yes <lab-host> true
MACRE_MACHINE="<lab-host>" bash scripts/install-ghidra-host.sh --smoke
```

Then read:

- `LAB_SAFETY.md`
- `machines.md`
- `CORPUS.md`
- `INDEX.md`
- `METRICS.md`
- `HANDOFF.md`
- the relevant `Skills/offensive-macos-*/SKILL.md`

Pick exactly one next artifact to produce: TSV, decompile note, candidate update, harness result, log capture, closure rationale, metrics update, handoff, or report draft.

## Troubleshooting

`ghidra-mcp` does not appear in Cursor:

- Check `~/.cursor/mcp.json`.
- Fully restart Cursor.
- Run `ssh <lab-host> /Users/<remote-user>/bin/ghidra-mcp-launch --version`.

SSH fails:

- Check `~/.ssh/config`.
- Run `ssh -v <lab-host> true`.
- Re-run `MACRE_MACHINE=<lab-host> bash scripts/install-vm-ssh-key.sh`.

Ghidra import or decompile is slow:

- First import is expensive.
- Reuse the same Ghidra project/session when possible.
- Narrow the binary slice instead of importing an entire app tree at once.

Script not found on the lab host:

- Re-run `MACRE_MACHINE=<lab-host> bash scripts/install-ghidra-host.sh --install`.
- Verify `ssh <lab-host> 'ls ~/ghidra-scripts'`.

Dynamic probe feels risky:

- Stop and read `LAB_SAFETY.md`.
- Move to a crash-test host or disposable user.
- Snapshot first.
- Ask Cursor to write a confirmation plan before running anything.

## What Good Output Looks Like

Good station output is not "I looked at a binary." Good output is:

- a target recorded in `CORPUS.md`
- a repeatable TSV under `findings/analysis/`
- a ranked candidate in `INDEX.md`
- a decompiled function tied to a hypothesis
- a dynamic result that confirms or closes the hypothesis
- metrics updated in `METRICS.md`
- artifacts saved under `artifacts/`
- a handoff that lets the next session resume quickly
- a report packet when the bug is real

## Operating Boundary

This station is for authorized reverse engineering, lab reproduction, root-cause analysis, defensive validation, remediation guidance, and reporting. It is not for persistence, evasion, command-and-control, deployment tradecraft, or live exploitation workflow.
