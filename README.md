# Skillz macOS Bug-Hunting Station

This repo is a Cursor-driven macOS reverse-engineering and bug-hunting station. Clone it when you want to start a new authorized reversing project.

## What Is In This Repo

- `Skills/` — Cursor skills for macOS RE, Ghidra tooling, hunt playbooks, reporting, and lab discipline.
- `docs/operator-guide.md` — human-facing guide for starting and running a hunt project.
- `docs/ontology/` — shared macOS vulnerability-class ontology.
- `docs/playbooks/` — third-party app family playbooks.
- `ghidra-scripts/` — read-only Ghidra postScripts that produce stable TSV triage output.
- `templates/findings-repo/` — starter template for private research repos.
- `scripts/` — setup, sync, and smoke-test helpers.

## What Does Not Belong Here

Do not push real target apps, private PoCs, logs, screenshots, crash reports, authorization records, or customer/client research artifacts to the public template repo. Keep that work in your private project clone.

## Station Setup

From this repo:

```bash
cd ~/tools/skillz
bash scripts/install-vm-ssh-key.sh
bash scripts/deploy-macre-vm-mcp.sh
bash scripts/install-ghidra-host.sh --install
bash scripts/install-ghidra-host.sh --smoke
```

After editing `~/.cursor/mcp.json`, fully restart Cursor so the MCP tool list refreshes.

## Starting A New Research Project

Clone this repo for each new project:

```bash
mkdir -p ~/re
cd ~/re
git clone https://github.com/UnsaltedHash42/mac-reversing-station <program-name>
cd <program-name>
rsync -a --ignore-existing templates/findings-repo/ ./
cp -n HANDOFF.md.template HANDOFF.md
cp -n machines.md.template machines.md
bash scripts/smoke-findings-repo.sh
```

Open `~/re/<program-name>` in Cursor with **File -> Open Folder...**. Fill in `AUTHORIZATION.md`, `LAB_SAFETY.md`, and `CORPUS.md` before asking the agent to analyze a test app.

See `docs/operator-guide.md` for the human workflow.

## Validation

Run structural checks:

```bash
bash scripts/smoke-wave3.sh
```

Run live workstation checks too:

```bash
bash scripts/smoke-wave3.sh --live
```

The default smoke is portable and does not require the NightBlood VM. `--live` checks NightBlood, Ghidra MCP, and the Wave 2 live path.

## Operating Boundary

This station is for authorized lab reproduction, root-cause analysis, metrics, and reporting. It is not for persistence, evasion, command-and-control, deployment tradecraft, or live exploitation workflow.
