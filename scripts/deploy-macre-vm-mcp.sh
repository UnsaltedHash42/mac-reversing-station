#!/usr/bin/env bash
# Deploy macre-vm-mcp to NightBlood.
#
# - Syncs the package source to ~/macre-vm-mcp on the VM.
# - Creates/updates a ~/.venvs/macre-vm-mcp venv against the homebrew python.
# - Installs the package editable so further pushes are a no-venv-rebuild.
# - Smoke-tests `python -m macre_vm_mcp --help` (if --help is supported)
#   and `python -c "from macre_vm_mcp.server import build_server; build_server()"`.
#
# Idempotent. Safe to re-run.
set -euo pipefail

HOST="NightBlood"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/macre-vm-mcp"
REMOTE_SRC="/Users/szeth/macre-vm-mcp"
REMOTE_VENV="/Users/szeth/.venvs/macre-vm-mcp"
REMOTE_PYTHON="/opt/homebrew/bin/python3"

if [[ ! -d "${SRC_DIR}" ]]; then
    echo "ERROR: source dir not found at ${SRC_DIR}" >&2
    exit 2
fi

echo "==> Syncing ${SRC_DIR}/ to ${HOST}:${REMOTE_SRC}/"
rsync -az --delete --exclude .venv --exclude __pycache__ --exclude '*.egg-info' \
    -e "ssh -o BatchMode=yes" \
    "${SRC_DIR}/" "${HOST}:${REMOTE_SRC}/"

echo "==> Ensuring venv at ${HOST}:${REMOTE_VENV}"
ssh -o BatchMode=yes "${HOST}" "bash -lc '
    set -e
    if [[ ! -d \"${REMOTE_VENV}\" ]]; then
        ${REMOTE_PYTHON} -m venv \"${REMOTE_VENV}\"
    fi
    \"${REMOTE_VENV}/bin/pip\" install --quiet --upgrade pip
    \"${REMOTE_VENV}/bin/pip\" install --quiet -e \"${REMOTE_SRC}\"
'"

echo "==> Smoke-testing server build on ${HOST}"
ssh -o BatchMode=yes "${HOST}" "bash -lc '
    \"${REMOTE_VENV}/bin/python\" -c \"from macre_vm_mcp.server import build_server; s = build_server(); print(\\\"tools:\\\", len([t for t in __import__(\\\"asyncio\\\").run(s.list_tools())]))\"
'"

echo ""
echo "OK — macre-vm-mcp deployed. Register in ~/.cursor/mcp.json:"
cat <<'JSON'
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
JSON
