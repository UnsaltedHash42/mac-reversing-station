#!/usr/bin/env bash
# Install /etc/sudoers.d/lab-nopasswd on a disposable lab host so the
# workstation agent can drive sudo-bound steps over non-interactive ssh
# (pkg installer, launchctl load, codesign --remove-signature, etc.).
#
# Gated on lab disposability. The fragment grants NOPASSWD: ALL to the
# lab user — only safe on hosts the operator has declared disposable in
# LAB_SAFETY.md (`lab_disposable: true`) and that hold no real data.
#
# Idempotent. Validates the fragment with `visudo -cf` before install.
#
# Usage:
#   MACRE_MACHINE=<lab-host> scripts/install-disposable-sudoers.sh [password]
#
# `password` is the lab user's account password, used once via /usr/bin/expect
# to drive `sudo -S`. After this script succeeds, future ssh-driven sudo
# calls run without prompts.
set -euo pipefail

HOST_ALIAS="${MACRE_MACHINE:-lab-host}"
VM_PASSWORD="${1:-${MACRE_VM_PASSWORD:-offsec}}"

if ! command -v expect >/dev/null 2>&1; then
    echo "ERROR: /usr/bin/expect not available" >&2
    exit 3
fi

REMOTE_USER=$(ssh -o BatchMode=yes -o ConnectTimeout=5 "${HOST_ALIAS}" 'id -un' 2>/dev/null || true)
if [[ -z "${REMOTE_USER}" ]]; then
    echo "ERROR: cannot resolve remote username over key-auth ssh to ${HOST_ALIAS}." >&2
    echo "Run scripts/install-vm-ssh-key.sh first." >&2
    exit 4
fi

# Fast path: if NOPASSWD sudo already works for this user, no-op.
if ssh -o BatchMode=yes -o ConnectTimeout=5 "${HOST_ALIAS}" 'sudo -n true' 2>/dev/null; then
    echo "OK: NOPASSWD sudo for ${REMOTE_USER}@${HOST_ALIAS} already works (no-op)."
    exit 0
fi

SUDOERS_FRAGMENT="${REMOTE_USER} ALL=(ALL) NOPASSWD: ALL"
SUDOERS_PATH="/etc/sudoers.d/lab-nopasswd-${REMOTE_USER}"

# The remote one-liner: write the fragment to a temp file, validate it with
# `visudo -cf`, then atomically install it under /etc/sudoers.d/. Bail loudly
# on any step. Owned by root:wheel, mode 0440 (sudo refuses anything else).
REMOTE_SCRIPT="set -e
TMP=\$(mktemp /tmp/lab-nopasswd.XXXXXX)
trap 'rm -f \$TMP' EXIT
printf '%s\\n' '${SUDOERS_FRAGMENT}' > \$TMP
chmod 0440 \$TMP
if ! sudo -S /usr/sbin/visudo -cf \$TMP > /dev/null 2>&1; then
    echo VISUDO_REJECTED_FRAGMENT >&2
    exit 5
fi
sudo -S install -m 0440 -o root -g wheel \$TMP '${SUDOERS_PATH}'
echo SUDOERS_INSTALLED:'${SUDOERS_PATH}'"

REMOTE_B64=$(printf '%s' "${REMOTE_SCRIPT}" | base64 | tr -d '\n')

# Drive the password prompt with /usr/bin/expect. `sudo -S` reads from stdin,
# so we hand it the password via the pipe; expect supplies the password if
# the agent's ssh session ever falls back to a password prompt instead.
/usr/bin/expect <<EOF
set timeout 30
spawn ssh -o BatchMode=no "${HOST_ALIAS}" "echo ${VM_PASSWORD} | base64 -d <<<'${REMOTE_B64}' | bash"
expect {
    -re "(\\\$|#) $"     { exp_continue }
    "password:"          { send -- "${VM_PASSWORD}\r"; exp_continue }
    "Password:"          { send -- "${VM_PASSWORD}\r"; exp_continue }
    "VISUDO_REJECTED_FRAGMENT" {
        puts "FATAL: visudo rejected the generated fragment; aborting before install."
        exit 5
    }
    timeout              { puts "TIMEOUT during remote install"; exit 6 }
    eof                  { }
}
catch wait result
exit [lindex \$result 3]
EOF

echo ""
echo "Verifying NOPASSWD sudo over non-interactive ssh..."
if ssh -o BatchMode=yes -o ConnectTimeout=5 "${HOST_ALIAS}" 'sudo -n true' 2>/dev/null; then
    echo "OK: ${REMOTE_USER}@${HOST_ALIAS} can sudo without a password."
    echo "Removed friction for: pkg installer, launchctl load, codesign edits, helper restart."
    echo ""
    echo "Revoke at any time with:"
    echo "  ssh ${HOST_ALIAS} sudo rm '${SUDOERS_PATH}'"
else
    echo "FAIL: NOPASSWD sudo still does not work." >&2
    echo "Check the remote /etc/sudoers.d/ for syntax issues:" >&2
    echo "  ssh ${HOST_ALIAS} sudo visudo -c" >&2
    exit 7
fi
