#!/usr/bin/env bash
# Idempotent one-shot: deploy the workstation's ed25519 public key into
# the primary lab host's ~/.ssh/authorized_keys so MCP servers can invoke
# ssh non-interactively.
#
# Requires: /usr/bin/expect (ships with macOS), an existing ~/.ssh/id_ed25519.pub,
# and a reachable lab host alias in ~/.ssh/config.
#
# Usage: MACRE_MACHINE=<lab-host> scripts/install-vm-ssh-key.sh [password]
#        Falls back to the default lab password if none is passed.
set -euo pipefail

PUBKEY_PATH="${HOME}/.ssh/id_ed25519.pub"
HOST_ALIAS="${MACRE_MACHINE:-lab-host}"
VM_PASSWORD="${1:-offsec}"

if [[ ! -f "${PUBKEY_PATH}" ]]; then
    echo "ERROR: public key not found at ${PUBKEY_PATH}" >&2
    echo "Generate one with: ssh-keygen -t ed25519 -N '' -f ${HOME}/.ssh/id_ed25519" >&2
    exit 2
fi

if ! command -v expect >/dev/null 2>&1; then
    echo "ERROR: /usr/bin/expect not available" >&2
    exit 3
fi

# Fast path: if non-interactive key auth already works, don't touch anything.
if ssh -o BatchMode=yes -o PreferredAuthentications=publickey -o ConnectTimeout=5 "${HOST_ALIAS}" true 2>/dev/null; then
    echo "OK: non-interactive key auth to ${HOST_ALIAS} already works (no-op)."
    exit 0
fi

PUBKEY_CONTENT="$(cat "${PUBKEY_PATH}")"

# Build the remote one-liner; base64-encode to survive quoting through expect/ssh.
REMOTE_SCRIPT="set -e
umask 077
mkdir -p \"\$HOME/.ssh\"
chmod 700 \"\$HOME/.ssh\"
touch \"\$HOME/.ssh/authorized_keys\"
chmod 600 \"\$HOME/.ssh/authorized_keys\"
if grep -qxF '${PUBKEY_CONTENT}' \"\$HOME/.ssh/authorized_keys\"; then
    echo KEY_ALREADY_PRESENT
else
    printf '%s\\n' '${PUBKEY_CONTENT}' >> \"\$HOME/.ssh/authorized_keys\"
    echo KEY_APPENDED
fi"
REMOTE_B64=$(printf '%s' "${REMOTE_SCRIPT}" | base64 | tr -d '\n')

# Drive ssh via expect to answer the one password prompt non-interactively.
# Plain-string patterns only; Tcl regex escaping is error-prone.
/usr/bin/expect <<EOF
set timeout 20
spawn ssh -o StrictHostKeyChecking=accept-new -o PreferredAuthentications=password -o PubkeyAuthentication=no ${HOST_ALIAS} "echo ${REMOTE_B64} | base64 -d | bash"
expect {
    "password:" { send -- "${VM_PASSWORD}\r" }
    "yes/no"    { send -- "yes\r"; exp_continue }
    timeout     { puts "TIMEOUT waiting for password prompt"; exit 1 }
}
expect eof
catch wait result
exit [lindex \$result 3]
EOF

echo ""
echo "Now verifying non-interactive key auth..."
if ssh -o BatchMode=yes -o PreferredAuthentications=publickey -o ConnectTimeout=5 "${HOST_ALIAS}" true 2>/dev/null; then
    echo "OK: non-interactive key auth to ${HOST_ALIAS} works."
else
    echo "FAIL: non-interactive key auth still not working." >&2
    echo "Check ~/.ssh/config for ${HOST_ALIAS} (PubkeyAuthentication must be yes), then re-run." >&2
    exit 4
fi
