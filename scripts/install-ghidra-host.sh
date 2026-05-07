#!/usr/bin/env bash
# Install or verify the Ghidra host side of the macOS bug-hunting station.
#
# This script targets the current primary lab machine, NightBlood. It installs:
# - Eclipse Temurin JDK 21 under ~/Applications/
# - Ghidra 12.0.4 under ~/Applications/
# - mrphrazer/ghidra-headless-mcp pinned from main under ~/tools/ghidra-headless-mcp/
# - compatibility launch/status scripts under ~/bin/ for Cursor's SSH stdio MCP entry.
#
# Idempotent. Safe to re-run.
set -euo pipefail

HOST="${MACRE_MACHINE:-NightBlood}"
REMOTE_HOME="/Users/szeth"
REMOTE_APPS="${REMOTE_HOME}/Applications"
REMOTE_TOOLS="${REMOTE_HOME}/tools/ghidra-mcp"
REMOTE_HEADLESS_SRC="${REMOTE_HOME}/tools/ghidra-headless-mcp"
REMOTE_BIN="${REMOTE_HOME}/bin"
REMOTE_VENV="${REMOTE_HOME}/.venvs/ghidra-mcp"
REMOTE_HEADLESS_VENV="${REMOTE_HOME}/.venvs/ghidra-headless-mcp"
REMOTE_GHIDRA="${REMOTE_APPS}/ghidra_12.0.4_PUBLIC"
REMOTE_JDK="${REMOTE_APPS}/jdk-21.0.11+10/Contents/Home"
REMOTE_CACHE="${REMOTE_HOME}/.cache/macre-ghidra"
LOCAL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_GHIDRA_SCRIPTS="${LOCAL_ROOT}/ghidra-scripts"
REMOTE_GHIDRA_SCRIPTS="${REMOTE_HOME}/ghidra-scripts"

GHIDRA_VERSION="12.0.4"
GHIDRA_DATE="20260303"
GHIDRA_SHA256="c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120"
GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip"

JDK_VERSION="21.0.11_10"
JDK_SHA256="6ebcf221c9b41507b14c098e93c6ead6440b8d9bd154f8ec666c4c73abbdb201"
JDK_URL="https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.11%2B10/OpenJDK21U-jdk_aarch64_mac_hotspot_${JDK_VERSION}.tar.gz"

UV_VERSION="0.11.11"
UV_SHA256="3a185bf8f46a7b7c8b910d111825907b1638d0ae503cb3c333ae205772354046"
UV_URL="https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-aarch64-apple-darwin.tar.gz"

GHIDRA_MCP_VERSION="5.6.0"
GHIDRA_MCP_ZIP_SHA256="5750435a6a4a920076586b471182ba9c98289ec2524cd52564d21c81610a4ef0"
GHIDRA_MCP_BRIDGE_SHA256="d63c4d65b80c93e7ebaa0fdcad23735071c573ef0343100d2da7c776f70796d1"
GHIDRA_MCP_REQUIREMENTS_SHA256="833cb35378ab21856c6d00735425004ec605a70b0d7a8b63841fcf97cd726a49"
GHIDRA_MCP_BASE_URL="https://github.com/bethington/ghidra-mcp/releases/download/v${GHIDRA_MCP_VERSION}"

HEADLESS_MCP_REPO="https://github.com/mrphrazer/ghidra-headless-mcp.git"
HEADLESS_MCP_COMMIT="b9c491a6383dbc68c581e7fed16341ac47e7faba"

usage() {
    printf 'Usage: %s [--install|--check|--smoke]\n' "$(basename "$0")"
    printf '\n'
    printf 'Environment:\n'
    printf '  MACRE_MACHINE   SSH alias for the Ghidra host (default: NightBlood)\n'
}

remote_check() {
    ssh -o BatchMode=yes -o ConnectTimeout=5 "${HOST}" /bin/bash -s <<'REMOTE_CHECK'
set -euo pipefail
fail=0
for path in \
    "/Users/szeth/Applications/jdk-21.0.11+10/Contents/Home/bin/java" \
    "/Users/szeth/Applications/ghidra_12.0.4_PUBLIC/support/analyzeHeadless" \
    "/Users/szeth/tools/ghidra-headless-mcp/ghidra_headless_mcp.py" \
    "/Users/szeth/.venvs/ghidra-headless-mcp/bin/ghidra-headless-mcp" \
    "/Users/szeth/bin/ghidra-mcp-launch" \
    "/Users/szeth/bin/ghidra-mcp-server-start" \
    "/Users/szeth/bin/ghidra-mcp-server-status"
do
    if [[ ! -e "${path}" ]]; then
        echo "MISSING: ${path}" >&2
        fail=1
    fi
done

if [[ "${fail}" -ne 0 ]]; then
    exit 1
fi

export JAVA_HOME="/Users/szeth/Applications/jdk-21.0.11+10/Contents/Home"
export PATH="${JAVA_HOME}/bin:${PATH}"
"${JAVA_HOME}/bin/java" -version 2>&1 | sed -n '1p'
"/Users/szeth/Applications/ghidra_12.0.4_PUBLIC/support/analyzeHeadless" 2>&1 | sed -n '1,3p' || true
"/Users/szeth/bin/ghidra-mcp-launch" --version
REMOTE_CHECK
}

remote_smoke() {
    ssh -o BatchMode=yes -o ConnectTimeout=5 "${HOST}" /bin/bash -s <<'REMOTE_SMOKE'
set -euo pipefail
"/Users/szeth/bin/ghidra-mcp-launch" --version
"/Users/szeth/.venvs/ghidra-headless-mcp/bin/python" -m py_compile "/Users/szeth/tools/ghidra-headless-mcp/ghidra_headless_mcp.py"
"/Users/szeth/.venvs/ghidra-headless-mcp/bin/ghidra-headless-mcp" --fake-backend --version
"/Users/szeth/.venvs/ghidra-headless-mcp/bin/python" - <<'PY'
import json
import subprocess
import time

process = subprocess.Popen(
    ["/Users/szeth/bin/ghidra-mcp-launch"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1,
)
next_id = 1


def send(method, params=None):
    global next_id
    message = {"jsonrpc": "2.0", "id": next_id, "method": method}
    if params is not None:
        message["params"] = params
    process.stdin.write(json.dumps(message) + "\n")
    process.stdin.flush()
    next_id += 1
    return next_id - 1


def notify(method, params=None):
    message = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        message["params"] = params
    process.stdin.write(json.dumps(message) + "\n")
    process.stdin.flush()


def receive(timeout=180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = process.stdout.readline()
        if line:
            return json.loads(line)
        if process.poll() is not None:
            raise RuntimeError("server exited: " + process.stderr.read())
    raise TimeoutError("no MCP response")


def call_tool(name, arguments, timeout=180):
    request_id = send("tools/call", {"name": name, "arguments": arguments})
    while True:
        response = receive(timeout)
        if response.get("id") != request_id:
            continue
        if "error" in response:
            raise RuntimeError(f"{name} error: {response['error']}")
        return response["result"]


send(
    "initialize",
    {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "install-ghidra-host-smoke", "version": "1"},
    },
)
receive(30)
notify("notifications/initialized", {})

opened = call_tool(
    "program.open",
    {
        "path": "/bin/ls",
        "project_location": "/Users/szeth/ghidra-projects",
        "project_name": "wave2-smoke",
        "read_only": True,
        "update_analysis": True,
    },
    240,
)
session_id = (opened.get("structuredContent") or {}).get("session_id")
if not session_id:
    raise RuntimeError("program.open did not return a session_id")

functions = call_tool("function.list", {"session_id": session_id, "limit": 20}, 120)
items = (functions.get("structuredContent") or {}).get("items") or []
if not items:
    raise RuntimeError("function.list returned no functions")

entry = items[0].get("entry_point")
decomp = call_tool(
    "decomp.function",
    {"session_id": session_id, "function_start": entry, "timeout_secs": 60},
    120,
)
if not ((decomp.get("structuredContent") or {}).get("c")):
    raise RuntimeError("decomp.function returned no C output")

script = call_tool(
    "ghidra.script",
    {
        "session_id": session_id,
        "path": "/Users/szeth/ghidra-scripts/scan_wrong_door.py",
        "script_args": [],
    },
    120,
)
stdout = (script.get("structuredContent") or {}).get("stdout", "")
if "daemon\tlisteners\tent_refs\tshould_accept_impls\taudit_token_uses\tevidence" not in stdout:
    raise RuntimeError("scan_wrong_door.py did not return expected TSV header")

process.terminate()
try:
    process.wait(timeout=5)
except subprocess.TimeoutExpired:
    process.kill()

print("OK - live ghidra-headless-mcp open/list/decompile/script smoke passed.")
PY
REMOTE_SMOKE
}

sync_ghidra_scripts() {
    if [[ ! -d "${LOCAL_GHIDRA_SCRIPTS}" ]]; then
        echo "WARN: ${LOCAL_GHIDRA_SCRIPTS} does not exist; skipping script sync" >&2
        return
    fi
    ssh -o BatchMode=yes "${HOST}" "mkdir -p '${REMOTE_GHIDRA_SCRIPTS}'"
    rsync -az --delete \
        -e "ssh -o BatchMode=yes" \
        "${LOCAL_GHIDRA_SCRIPTS}/" "${HOST}:${REMOTE_GHIDRA_SCRIPTS}/"
    echo "OK - synced ghidra-scripts to ${HOST}:${REMOTE_GHIDRA_SCRIPTS}/"
}

remote_install() {
    ssh -o BatchMode=yes -o ServerAliveInterval=30 "${HOST}" \
        GHIDRA_VERSION="${GHIDRA_VERSION}" \
        GHIDRA_URL="${GHIDRA_URL}" \
        GHIDRA_SHA256="${GHIDRA_SHA256}" \
        JDK_URL="${JDK_URL}" \
        JDK_SHA256="${JDK_SHA256}" \
        UV_URL="${UV_URL}" \
        UV_SHA256="${UV_SHA256}" \
        GHIDRA_MCP_VERSION="${GHIDRA_MCP_VERSION}" \
        GHIDRA_MCP_BASE_URL="${GHIDRA_MCP_BASE_URL}" \
        GHIDRA_MCP_ZIP_SHA256="${GHIDRA_MCP_ZIP_SHA256}" \
        GHIDRA_MCP_BRIDGE_SHA256="${GHIDRA_MCP_BRIDGE_SHA256}" \
        GHIDRA_MCP_REQUIREMENTS_SHA256="${GHIDRA_MCP_REQUIREMENTS_SHA256}" \
        HEADLESS_MCP_REPO="${HEADLESS_MCP_REPO}" \
        HEADLESS_MCP_COMMIT="${HEADLESS_MCP_COMMIT}" \
        REMOTE_APPS="${REMOTE_APPS}" \
        REMOTE_TOOLS="${REMOTE_TOOLS}" \
        REMOTE_HEADLESS_SRC="${REMOTE_HEADLESS_SRC}" \
        REMOTE_BIN="${REMOTE_BIN}" \
        REMOTE_VENV="${REMOTE_VENV}" \
        REMOTE_HEADLESS_VENV="${REMOTE_HEADLESS_VENV}" \
        REMOTE_GHIDRA="${REMOTE_GHIDRA}" \
        REMOTE_JDK="${REMOTE_JDK}" \
        REMOTE_CACHE="${REMOTE_CACHE}" \
        /bin/bash -s <<'REMOTE_INSTALL'
set -euo pipefail

download_if_needed() {
    local url="$1"
    local dest="$2"
    local expected_sha="$3"

    if [[ -f "${dest}" ]]; then
        local actual_sha
        actual_sha="$(shasum -a 256 "${dest}" | awk '{print $1}')"
        if [[ "${actual_sha}" == "${expected_sha}" ]]; then
            echo "OK cached: ${dest}"
            return
        fi
        echo "WARN checksum mismatch for cached ${dest}; re-downloading" >&2
        rm -f "${dest}"
    fi

    echo "Downloading ${url}"
    curl -fL --retry 3 --retry-delay 5 "${url}" -o "${dest}"
    local actual_sha
    actual_sha="$(shasum -a 256 "${dest}" | awk '{print $1}')"
    if [[ "${actual_sha}" != "${expected_sha}" ]]; then
        echo "ERROR checksum mismatch for ${dest}" >&2
        echo "expected ${expected_sha}" >&2
        echo "actual   ${actual_sha}" >&2
        exit 2
    fi
}

write_file() {
    local path="$1"
    shift
    python3 -c 'from pathlib import Path; import os, sys; path = Path(sys.argv[1]); mode = int(sys.argv[2], 8); path.parent.mkdir(parents=True, exist_ok=True); path.write_text(sys.stdin.read(), encoding="utf-8"); os.chmod(path, mode)' "$path" "$@"
}

mkdir -p "${REMOTE_APPS}" "${REMOTE_TOOLS}" "${REMOTE_BIN}" "${REMOTE_CACHE}" "${HOME}/Library/Logs/ghidra-mcp"

if [[ ! -x "${REMOTE_JDK}/bin/java" ]]; then
    jdk_archive="${REMOTE_CACHE}/temurin-jdk21-aarch64-mac.tar.gz"
    download_if_needed "${JDK_URL}" "${jdk_archive}" "${JDK_SHA256}"
    echo "Installing Temurin JDK 21 to ${REMOTE_APPS}"
    tar -xzf "${jdk_archive}" -C "${REMOTE_APPS}"
else
    echo "OK JDK already installed at ${REMOTE_JDK}"
fi

if [[ ! -x "${REMOTE_BIN}/uv" ]]; then
    uv_archive="${REMOTE_CACHE}/uv-aarch64-apple-darwin.tar.gz"
    download_if_needed "${UV_URL}" "${uv_archive}" "${UV_SHA256}"
    echo "Installing uv to ${REMOTE_BIN}"
    uv_tmp="$(mktemp -d)"
    tar -xzf "${uv_archive}" -C "${uv_tmp}"
    install -m 0755 "${uv_tmp}/uv-aarch64-apple-darwin/uv" "${REMOTE_BIN}/uv"
    if [[ -x "${uv_tmp}/uv-aarch64-apple-darwin/uvx" ]]; then
        install -m 0755 "${uv_tmp}/uv-aarch64-apple-darwin/uvx" "${REMOTE_BIN}/uvx"
    fi
    rm -rf "${uv_tmp}"
else
    echo "OK uv already installed at ${REMOTE_BIN}/uv"
fi

if [[ ! -x "${REMOTE_GHIDRA}/support/analyzeHeadless" ]]; then
    ghidra_archive="${REMOTE_CACHE}/ghidra_${GHIDRA_VERSION}.zip"
    download_if_needed "${GHIDRA_URL}" "${ghidra_archive}" "${GHIDRA_SHA256}"
    echo "Installing Ghidra ${GHIDRA_VERSION} to ${REMOTE_APPS}"
    unzip -q -o "${ghidra_archive}" -d "${REMOTE_APPS}"
    chmod +x "${REMOTE_GHIDRA}/support/analyzeHeadless" "${REMOTE_GHIDRA}/ghidraRun"
else
    echo "OK Ghidra already installed at ${REMOTE_GHIDRA}"
fi

mcp_zip="${REMOTE_CACHE}/GhidraMCP-${GHIDRA_MCP_VERSION}.zip"
mcp_bridge="${REMOTE_TOOLS}/bridge_mcp_ghidra.py"
mcp_requirements="${REMOTE_TOOLS}/requirements.txt"
download_if_needed "${GHIDRA_MCP_BASE_URL}/GhidraMCP-${GHIDRA_MCP_VERSION}.zip" "${mcp_zip}" "${GHIDRA_MCP_ZIP_SHA256}"
download_if_needed "${GHIDRA_MCP_BASE_URL}/bridge_mcp_ghidra.py" "${mcp_bridge}" "${GHIDRA_MCP_BRIDGE_SHA256}"
download_if_needed "${GHIDRA_MCP_BASE_URL}/requirements.txt" "${mcp_requirements}" "${GHIDRA_MCP_REQUIREMENTS_SHA256}"

echo "Installing GhidraMCP extension files"
rm -rf "${REMOTE_TOOLS}/GhidraMCP"
unzip -q -o "${mcp_zip}" -d "${REMOTE_TOOLS}"

if [[ -x "${REMOTE_VENV}/bin/python" ]]; then
    venv_ok="$("${REMOTE_VENV}/bin/python" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' && printf yes || printf no)"
else
    venv_ok="no"
fi
if [[ "${venv_ok}" != "yes" ]]; then
    rm -rf "${REMOTE_VENV}"
    "${REMOTE_BIN}/uv" venv --python 3.12 "${REMOTE_VENV}"
fi
"${REMOTE_BIN}/uv" pip install --python "${REMOTE_VENV}/bin/python" --quiet --upgrade pip
"${REMOTE_BIN}/uv" pip install --python "${REMOTE_VENV}/bin/python" --quiet -r "${mcp_requirements}"

if [[ ! -d "${REMOTE_HEADLESS_SRC}/.git" ]]; then
    rm -rf "${REMOTE_HEADLESS_SRC}"
    git clone "${HEADLESS_MCP_REPO}" "${REMOTE_HEADLESS_SRC}"
fi
git -C "${REMOTE_HEADLESS_SRC}" fetch --quiet origin
git -C "${REMOTE_HEADLESS_SRC}" checkout --quiet "${HEADLESS_MCP_COMMIT}"

if [[ -x "${REMOTE_HEADLESS_VENV}/bin/python" ]]; then
    headless_venv_ok="$("${REMOTE_HEADLESS_VENV}/bin/python" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' && printf yes || printf no)"
else
    headless_venv_ok="no"
fi
if [[ "${headless_venv_ok}" != "yes" ]]; then
    rm -rf "${REMOTE_HEADLESS_VENV}"
    "${REMOTE_BIN}/uv" venv --python 3.12 "${REMOTE_HEADLESS_VENV}"
fi
"${REMOTE_BIN}/uv" pip install --python "${REMOTE_HEADLESS_VENV}/bin/python" --quiet --upgrade pip
"${REMOTE_BIN}/uv" pip install --python "${REMOTE_HEADLESS_VENV}/bin/python" --quiet -e "${REMOTE_HEADLESS_SRC}"

write_file "${REMOTE_BIN}/ghidra-mcp-server-start" 0755 <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
echo "OK - ghidra-headless-mcp uses stdio and starts on demand via ghidra-mcp-launch"
SCRIPT

write_file "${REMOTE_BIN}/ghidra-mcp-server-stop" 0755 <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
echo "OK - ghidra-headless-mcp has no persistent stdio daemon to stop"
SCRIPT

write_file "${REMOTE_BIN}/ghidra-mcp-server-status" 0755 <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
exec "/Users/szeth/bin/ghidra-mcp-launch" --version
SCRIPT

write_file "${REMOTE_BIN}/ghidra-mcp-launch" 0755 <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
export JAVA_HOME="/Users/szeth/Applications/jdk-21.0.11+10/Contents/Home"
export PATH="${JAVA_HOME}/bin:${PATH}"
GHIDRA_HOME="/Users/szeth/Applications/ghidra_12.0.4_PUBLIC"

case "${1:-}" in
    --version)
        "${JAVA_HOME}/bin/java" -version 2>&1 | sed -n '1p'
        "/Users/szeth/.venvs/ghidra-headless-mcp/bin/python" --version
        printf 'Ghidra 12.0.4\nghidra-headless-mcp b9c491a6383dbc68c581e7fed16341ac47e7faba\n'
        "/Users/szeth/.venvs/ghidra-headless-mcp/bin/ghidra-headless-mcp" --version
        exit 0
        ;;
    --check)
        exec "/Users/szeth/bin/ghidra-mcp-server-status"
        ;;
    --server-start)
        exec "/Users/szeth/bin/ghidra-mcp-server-start"
        ;;
    --server-stop)
        exec "/Users/szeth/bin/ghidra-mcp-server-stop"
        ;;
esac

exec "/Users/szeth/.venvs/ghidra-headless-mcp/bin/ghidra-headless-mcp" \
    --ghidra-install-dir "${GHIDRA_HOME}" \
    "$@"
SCRIPT

echo "OK - install complete"
REMOTE_INSTALL
}

case "${1:---install}" in
    --install)
        remote_install
        sync_ghidra_scripts
        remote_check
        ;;
    --check)
        remote_check
        ;;
    --smoke)
        remote_smoke
        ;;
    -h|--help)
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
