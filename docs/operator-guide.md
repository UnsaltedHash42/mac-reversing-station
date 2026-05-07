# macOS Bug-Hunting Station — Operator Guide

> **Audience:** the operator using Cursor as the cockpit for authorized macOS vulnerability research.
> **Goal:** start a new private hunt, use the station correctly, and produce submission-quality evidence.
> **Reference sibling:** topology details live in `docs/topology.md`; skill inventory lives in `docs/workstation/skill-bundles.md`.

## 1. What This Station Is

This is a bug-hunting station, not a classroom. The core loop is:

```text
findings repo -> attach hunt skill -> Ghidra breadth sweep -> TSV triage -> dynamic proof -> submission packet
```

The workstation runs Cursor and stores durable research state. NightBlood is the current primary lab host: it runs Ghidra 12.0.4 headless, `ghidra-mcp`, `macre-vm-mcp`, and optional GUI Hopper for human depth work. Cursor talks to NightBlood over SSH stdio MCP.

Hopper is no longer in the agent loop. It can still be opened manually on NightBlood when a human wants a GUI view, but agents should use `ghidra-mcp` for static analysis.

## 2. One-Time Station Setup

Run from the station repo:

```bash
cd ~/tools/skillz
./cursor/skill-link.sh
bash scripts/install-vm-ssh-key.sh
bash scripts/deploy-macre-vm-mcp.sh
bash scripts/install-ghidra-host.sh --install
bash scripts/install-ghidra-host.sh --smoke
```

Expected `--smoke` result:

- Java 21 prints.
- Python 3.12 prints.
- Ghidra 12.0.4 prints.
- `ghidra-headless-mcp` prints.
- `/bin/ls` opens in Ghidra.
- Function listing works.
- Decompilation works.
- `scan_wrong_door.py` returns TSV.

Cursor MCP config should include:

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

and:

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

After changing `~/.cursor/mcp.json`, fully restart Cursor so the tool list refreshes.

## 3. Starting A New Hunt Project

Each real research project starts by cloning this station repo. Your project clone contains the station docs, skills, scripts, Ghidra sweep scripts, and local findings files. Your target apps, screenshots, logs, PoCs, metrics, notes, and authorization details stay in that private project clone and should not be pushed back to the public template repo.

### Option A: Start From The Station Repo

Use this for normal projects.

1. Open Terminal.
2. Clone the station repo under `~/re/`.

```bash
mkdir -p ~/re
cd ~/re
git clone https://github.com/UnsaltedHash42/mac-reversing-station <program-name>
cd <program-name>
```

3. Add the local findings files from the included template.

```bash
rsync -a --ignore-existing templates/findings-repo/ ./
cp -n HANDOFF.md.template HANDOFF.md
cp -n machines.md.template machines.md
bash scripts/smoke-findings-repo.sh
```

4. Open the cloned repo in Cursor:
   - Cursor menu: **File -> Open Folder...**
   - Pick `~/re/<program-name>`
   - Confirm the file tree shows `AUTHORIZATION.md`, `CORPUS.md`, `METRICS.md`, `INDEX.md`, and `HANDOFF.md`

### Option B: Start Without A Repo

Use this only when you already have a local copy of the station at `~/tools/skillz`.

```bash
mkdir -p ~/re
cp -R ~/tools/skillz ~/re/<program-name>
cd ~/re/<program-name>
rm -rf .git
git init
rsync -a --ignore-existing templates/findings-repo/ ./
cp HANDOFF.md.template HANDOFF.md
cp machines.md.template machines.md
bash scripts/smoke-findings-repo.sh
```

Open `~/re/<program-name>` in Cursor with **File -> Open Folder...**.

### First Files To Fill In

Do these before asking the agent to hunt.

1. Open `AUTHORIZATION.md`.
   - Write what you are allowed to reverse.
   - List the test apps/components.
   - List anything out of scope.
2. Open `LAB_SAFETY.md`.
   - Fill in `NightBlood` as primary if you are using it.
   - Write which user/profile is disposable.
   - Confirm whether snapshots exist before destructive tests.
3. Open `CORPUS.md`.
   - Create the first pass ID, for example `PASS-001`.
   - Pick one target family.
   - Add the test app version and source.
4. Open `HANDOFF.md`.
   - Write the first thing you want the station to produce.
5. Leave `INDEX.md` and `METRICS.md` empty until the first scan produces candidates.

### First Cursor Prompt

Paste this into Cursor chat from inside the findings repo:

```text
We are in REPO_MODE=analysis. Use the macOS station skills from ~/tools/skillz/Skills.

I am the human operator. Guide me step by step. Tell me what to open, what to run, and what evidence to save.

Start PASS-001 for <target family> against <test app/component>. First read AUTHORIZATION.md, LAB_SAFETY.md, CORPUS.md, METRICS.md, INDEX.md, and HANDOFF.md. Then map the target to the macOS vulnerability ontology, propose the first static sweep, and save outputs under findings/analysis/.
```

Replace `<target family>` with one of:

- privileged helpers / updaters
- enterprise / security agents
- developer tools
- TCC-heavy consumer apps

Replace `<test app/component>` with the app you are testing.

## 4. Human Workflow

This section is written for you, the person pressing buttons and looking at screens.

### Step 1: Choose The Project Window

You should normally have two folders available:

- `~/tools/skillz` — station code, docs, skills, scripts.
- `~/re/<program-name>` — the private project you are actively hunting in.

In Cursor, open the private findings repo, not `skillz`, when doing real research. The chat should operate from the findings repo so generated files land in the right place.

### Step 2: Pick A Target Family

For Wave 3 third-party app research, start with one target family:

- Privileged helpers / updaters: `Skills/offensive-macos-family-privileged-helpers/SKILL.md`
- Enterprise / security agents: `Skills/offensive-macos-family-enterprise-agents/SKILL.md`
- Developer tools: `Skills/offensive-macos-family-developer-tools/SKILL.md`
- TCC-heavy consumer apps: `Skills/offensive-macos-family-tcc-heavy-apps/SKILL.md`

Then map surfaces to the ontology:

- `Skills/offensive-macos-vuln-ontology/SKILL.md`
- `docs/ontology/macos-vulnerability-classes.md`

Wave 2 seed classes are still useful and can be used when the target points directly at them:

- Wrong-door XPC entitlement gaps: `Skills/offensive-macos-hunt-wrong-door/SKILL.md`
- User-defaults security bypasses: `Skills/offensive-macos-hunt-defaults-bypass/SKILL.md`
- Catalyst/platform porting gaps: `Skills/offensive-macos-hunt-catalyst-porting-gap/SKILL.md`

Do not ask the agent to "find bugs in macOS." Ask for one target family, one pass ID, one ontology slice, and one output artifact.

### Step 3: Put The Test App In The Corpus

For a normal `.app` bundle you downloaded or built:

1. Create a `targets/` directory in the findings repo.
2. Copy the app or binary into it.
3. Record the app name, version, source, and target family in `CORPUS.md`.

Example:

```bash
mkdir -p targets
cp -R "/Applications/<App Name>.app" targets/
```

If the app is not already installed, copy the downloaded `.dmg`, `.pkg`, or `.zip` into `targets/` but do not run it on your main user profile. Treat installers and updaters as untrusted until `LAB_SAFETY.md` says where they can run.

### Step 4: Build A Target Corpus

Examples:

```bash
mkdir -p targets
cp /usr/libexec/<daemon> targets/
cp -R /System/Library/PrivateFrameworks/<Name>.framework targets/
```

For third-party app research, store the inventory in `CORPUS.md` and record authorization in `AUTHORIZATION.md`. Treat unknown app bundles, installers, helpers, and updaters as untrusted until `LAB_SAFETY.md` says where they can run.

If the target must run on NightBlood, sync:

```bash
MACRE_PROJECT=<program-name> ~/tools/skillz/scripts/rsync-to-vm.sh targets/
```

### Step 5: Run A Ghidra Sweep

Ask Cursor to open the binary through `ghidra-mcp`. You do not need to manually type MCP JSON. From chat, ask for one script at a time.

Example prompt:

```text
Run a Ghidra static sweep for PASS-001. Use scan_xpc_client_validation.py and scan_privileged_helper_surface.py against the main binary in targets/<App Name>.app. Save TSV output under findings/analysis/ and update INDEX.md/METRICS.md with candidates or closures.
```

For each candidate binary, the agent should:

1. `program.open` with `project_location="/Users/szeth/ghidra-projects"`.
2. Run the class script with `ghidra.script`.
3. Save stdout to `findings/analysis/<date>-<class>-sweep.tsv`.

Script paths on NightBlood:

- `/Users/szeth/ghidra-scripts/scan_wrong_door.py`
- `/Users/szeth/ghidra-scripts/scan_defaults_bypass.py`
- `/Users/szeth/ghidra-scripts/scan_catalyst_porting_gap.py`
- `/Users/szeth/ghidra-scripts/scan_flags_zero.py`
- `/Users/szeth/ghidra-scripts/dump_xpc_listeners.py`
- `/Users/szeth/ghidra-scripts/scan_xpc_client_validation.py`
- `/Users/szeth/ghidra-scripts/scan_privileged_helper_surface.py`
- `/Users/szeth/ghidra-scripts/scan_tcc_prompt_surface.py`
- `/Users/szeth/ghidra-scripts/scan_persistent_authorization.py`

### Step 6: Triage Rows

After a TSV appears in `findings/analysis/`, open it in Cursor or a spreadsheet-like viewer. You are looking for rows that explain why they are interesting.

Rank rows into:

- Tier 1: strong static signal plus likely user reachability.
- Tier 2: static signal but unclear reachability or authorization location.
- Tier 3: weak signal, likely false positive, or root-only.

Every row should get one of: escalate, hold, close. "Interesting" is not a status.

For Wave 3 findings repos, use the lifecycle vocabulary in `INDEX.md` and update `METRICS.md` before ending the session. Closed false positives with rationale count as useful research output.

Human decision rule:

- If you understand why the row might cross a boundary, mark it `escalated`.
- If you need another pass later, mark it `hold`.
- If the row is expected behavior or gated correctly, mark it `closed` and write why.
- If setup is missing, mark it `blocked` and name the blocker.

### Step 7: Deep Dive One Candidate

Use `ghidra-mcp` to:

- Resolve relevant functions with `function.list` or `function.by_name`.
- Decompile with `decomp.function`.
- Trace strings, imports, and callers.
- Run a focused script if the built-in TSV is not enough.

Use `macre-vm-mcp` to:

- Dump entitlements and code-sign flags.
- Inspect launchd plists.
- Stream logs.
- Run LLDB or DTrace when static analysis is insufficient.

At this point you may also open Ghidra or Hopper manually on NightBlood if a GUI helps. The agent should still save durable notes back into the findings repo.

### Step 8: Dynamic Confirmation

Prefer smallest proof first:

- For wrong-door: UID 501 XPC reachability, then one harmless method.
- For defaults bypass: one `defaults write`, one daemon trigger, one log line proving branch influence.
- For Catalyst porting: native-vs-Catalyst behavior matrix.

Record command, machine, OS, SIP state, expected result, actual result, and artifact path.

Before you run anything that installs helpers, changes keychain state, modifies TCC, or could crash the machine, check `LAB_SAFETY.md`. If the row says the current profile is not disposable, stop and move the test.

### Step 9: Report Packet

When a candidate is confirmed, switch to `Skills/offensive-macos-submission-packet/SKILL.md` and choose the report mode:

- vendor disclosure
- internal remediation
- red-team report
- Apple / platform disclosure

Minimum packet:

- One-paragraph summary.
- Preconditions.
- Build/run steps.
- Expected vs actual.
- Root cause.
- Impact.
- Affected versions.
- Cross-platform matrix.
- Minimal PoC.
- Logs/crash evidence.

Do not include persistence, evasion, command-and-control, deployment, or operational chaining. If a finding affects both a third-party vendor and Apple/platform behavior, stop and choose coordination order before preparing multiple packets.

## 5. Machine Discipline

NightBlood is currently the primary. Use it for static analysis and routine dynamic probes.

Add the other roles as the lab grows:

- crash-test: panics and destructive daemon work.
- cross-platform: different Apple Silicon generation.
- intel-baseline: x86_64/macOS comparison.

Before a panic-prone run, stop and ask: "Am I on the crash-test machine?" If the answer is no, move the test or explicitly accept the risk.

## 6. Stuck Protocol

Use `Skills/offensive-macos-agent-discipline/SKILL.md`.

If you hit 10 minutes or 20 attempts without new evidence:

1. Stop the probe loop.
2. Classify the blocker L1-L6.
3. Save the last command and failure.
4. Start a Ghidra RE thread in parallel or close the hypothesis.

Do not keep mutating commands blindly.

## 7. Hopper Escape Hatch

Hopper remains useful for human visual inspection. Use it manually when:

- You want a second decompiler opinion.
- Ghidra's analysis is confusing.
- You are doing visual navigation that is faster by hand.

Do not route agent work through the old Hopper bridge. The active MCP route is `ghidra-mcp`.

## 8. Daily Start Checklist

From the findings repo:

```bash
bash scripts/smoke-findings-repo.sh
ssh -o BatchMode=yes NightBlood true
~/tools/skillz/scripts/install-ghidra-host.sh --smoke
```

Then read:

- `AUTHORIZATION.md`
- `LAB_SAFETY.md`
- `CORPUS.md`
- `METRICS.md`
- `HANDOFF.md`
- `INDEX.md`
- `SUBMISSION_TRIAGE.md`
- `REPORTING.md`
- relevant skill file

Pick exactly one next artifact to produce: TSV, decompile note, harness result, log capture, metrics update, closure rationale, or report draft.

## 9. Troubleshooting

`ghidra-mcp` missing in Cursor:

- Validate `~/.cursor/mcp.json`.
- Fully restart Cursor.
- Run `ssh NightBlood /Users/szeth/bin/ghidra-mcp-launch --version`.

Ghidra open/decompile is slow:

- First import is expensive. Reuse `session_id`.
- Use smaller target slices.
- Keep projects under `/Users/szeth/ghidra-projects`.

Script not found:

- Run `~/tools/skillz/scripts/install-ghidra-host.sh --install`.
- Verify `ssh NightBlood 'ls /Users/szeth/ghidra-scripts'`.

Dynamic probe ambiguity:

- Check `lsof`.
- Check unified logs.
- Confirm daemon PID before and after.
- Move to crash-test if the next action can kill or panic the target.

## 10. What Good Output Looks Like

Good station output is not "I read a binary." It is:

- A TSV with stable columns.
- A ranked candidate list.
- A decompiled function tied to a hypothesis.
- A dynamic result that confirms or closes the hypothesis.
- A metrics row that records candidates, closures, escalations, confirmed findings, and blockers.
- A handoff that lets the next session resume in five minutes.
- A report packet when the bug is real.
