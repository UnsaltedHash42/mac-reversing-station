#!/usr/bin/env bash
# One-shot workstation setup for the Keep.
#
# Run this from the clean station checkout on your workstation. It links Cursor
# skills, verifies SSH, installs lab-host tooling over SSH, writes Cursor MCP
# config, and runs smoke checks.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="${MACRE_MACHINE:-}"
REMOTE_HOME="${MACRE_REMOTE_HOME:-}"
REMOTE_PYTHON="${MACRE_REMOTE_PYTHON:-/opt/homebrew/bin/python3}"
VM_PASSWORD=""
INSTALL_SSH_KEY=1
INSTALL_GHIDRA=1
INSTALL_DYNAMIC=1
WRITE_MCP=1
WRITE_CURSOR=1
WRITE_CLAUDE_CODE=1
RUN_LIVE_SMOKE=0
INSTALL_DISPOSABLE_SUDOERS=0

usage() {
    cat <<'USAGE'
Usage:
  scripts/setup-keep.sh --host <lab-host> --remote-home /Users/<remote-user> [options]

Required:
  --host <alias>             SSH alias from ~/.ssh/config for the lab host
  --remote-home <path>       Remote user's home directory, e.g. /Users/reuser

Options:
  --remote-python <path>     Lab-host Python for macre-vm-mcp (default: /opt/homebrew/bin/python3)
  --vm-password <password>   Password for initial SSH key installation
  --skip-ssh-key             Do not install ~/.ssh/id_ed25519.pub on the lab host
  --skip-ghidra              Do not install or check Ghidra/ghidra-mcp
  --skip-dynamic             Do not deploy macre-vm-mcp
  --skip-mcp-config          Do not write MCP config for either Cursor or Claude Code
  --cursor-only              Only write Cursor config (skip Claude Code)
  --claude-code-only         Only write Claude Code config (skip Cursor)
  --live-smoke               Run live lab-host smoke checks after setup
  --lab-disposable           Install /etc/sudoers.d/lab-nopasswd-<user> on the
                             lab host so ssh-driven sudo runs without prompts
                             (pkg installer, launchctl load, codesign edits).
                             Only safe on hosts you've declared lab_disposable:
                             true in LAB_SAFETY.md. Requires --vm-password.
  -h, --help                 Show this help

Environment equivalents:
  MACRE_MACHINE, MACRE_REMOTE_HOME, MACRE_REMOTE_PYTHON
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)
            HOST="$2"; shift 2 ;;
        --remote-home)
            REMOTE_HOME="$2"; shift 2 ;;
        --remote-python)
            REMOTE_PYTHON="$2"; shift 2 ;;
        --vm-password)
            VM_PASSWORD="$2"; shift 2 ;;
        --skip-ssh-key)
            INSTALL_SSH_KEY=0; shift ;;
        --skip-ghidra)
            INSTALL_GHIDRA=0; shift ;;
        --skip-dynamic)
            INSTALL_DYNAMIC=0; shift ;;
        --skip-mcp-config)
            WRITE_MCP=0; shift ;;
        --cursor-only)
            WRITE_CLAUDE_CODE=0; shift ;;
        --claude-code-only)
            WRITE_CURSOR=0; shift ;;
        --live-smoke)
            RUN_LIVE_SMOKE=1; shift ;;
        --lab-disposable)
            INSTALL_DISPOSABLE_SUDOERS=1; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            usage >&2
            exit 2 ;;
    esac
done

if [[ -z "${HOST}" || -z "${REMOTE_HOME}" ]]; then
    echo "ERROR: --host and --remote-home are required." >&2
    usage >&2
    exit 2
fi

export MACRE_MACHINE="${HOST}"
export MACRE_REMOTE_HOME="${REMOTE_HOME}"
export MACRE_REMOTE_TARGETS="${MACRE_REMOTE_TARGETS:-${REMOTE_HOME}/Targets}"
export MACRE_REMOTE_PYTHON="${REMOTE_PYTHON}"

section() { printf '\n==> %s\n' "$1"; }

if [[ "${WRITE_CURSOR}" -eq 1 ]]; then
    section "Link Cursor skills"
    bash "${ROOT}/cursor/skill-link.sh"
fi

if [[ "${WRITE_CLAUDE_CODE}" -eq 1 ]]; then
    section "Link Claude Code skills"
    bash "${ROOT}/scripts/skill-link-claude-code.sh"
fi

section "Ensure local SSH key exists"
mkdir -p "${HOME}/.ssh"
if [[ -f "${HOME}/.ssh/id_ed25519" && ! -f "${HOME}/.ssh/id_ed25519.pub" ]]; then
    echo "OK - found private key without public key; deriving ${HOME}/.ssh/id_ed25519.pub"
    ssh-keygen -y -f "${HOME}/.ssh/id_ed25519" > "${HOME}/.ssh/id_ed25519.pub"
elif [[ ! -f "${HOME}/.ssh/id_ed25519.pub" ]]; then
    ssh-keygen -t ed25519 -N '' -f "${HOME}/.ssh/id_ed25519"
else
    echo "OK - found ${HOME}/.ssh/id_ed25519.pub"
fi

if [[ "${INSTALL_SSH_KEY}" -eq 1 ]]; then
    section "Install SSH key on lab host"
    if [[ -n "${VM_PASSWORD}" ]]; then
        bash "${ROOT}/scripts/install-vm-ssh-key.sh" "${VM_PASSWORD}"
    else
        bash "${ROOT}/scripts/install-vm-ssh-key.sh"
    fi
fi

section "Verify SSH"
ssh -o BatchMode=yes -o ConnectTimeout=5 "${HOST}" 'uname -m; sw_vers -productVersion'

if [[ "${INSTALL_GHIDRA}" -eq 1 ]]; then
    section "Install Ghidra and ghidra-mcp"
    bash "${ROOT}/scripts/install-ghidra-host.sh" --install
fi

if [[ "${INSTALL_DYNAMIC}" -eq 1 ]]; then
    section "Deploy macre-vm-mcp"
    bash "${ROOT}/scripts/deploy-macre-vm-mcp.sh"
fi

if [[ "${INSTALL_DISPOSABLE_SUDOERS}" -eq 1 ]]; then
    section "Install NOPASSWD sudoers fragment (disposable lab only)"
    if [[ -z "${VM_PASSWORD}" ]]; then
        echo "ERROR: --lab-disposable requires --vm-password (lab user account password)." >&2
        exit 2
    fi
    bash "${ROOT}/scripts/install-disposable-sudoers.sh" "${VM_PASSWORD}"
fi

if [[ "${WRITE_MCP}" -eq 1 && "${WRITE_CURSOR}" -eq 1 ]]; then
    section "Write Cursor MCP config"
    python3 "${ROOT}/scripts/configure-cursor-mcp.py" --host "${HOST}" --remote-home "${REMOTE_HOME}"
fi

if [[ "${WRITE_MCP}" -eq 1 && "${WRITE_CLAUDE_CODE}" -eq 1 ]]; then
    section "Write Claude Code MCP config"
    python3 "${ROOT}/scripts/configure-claude-code-mcp.py" --host "${HOST}" --remote-home "${REMOTE_HOME}"
fi

section "Run structural smoke"
bash "${ROOT}/scripts/smoke-wave3.sh"

if [[ "${RUN_LIVE_SMOKE}" -eq 1 ]]; then
    section "Run live smoke"
    bash "${ROOT}/scripts/smoke-wave3.sh" --live
else
    echo "Skip live smoke by default. Re-run with --live-smoke after Cursor/lab host setup if desired."
fi

cat <<EOF

OK - Keep setup complete.

Next:
  1. Restart Cursor and/or Claude Code so MCP config changes load.
  2. Open a project clone in your editor or run 'claude' from a project directory.
  3. Run: scripts/init-project.sh --name <project-name>
EOF
