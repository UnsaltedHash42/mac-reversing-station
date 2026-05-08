#!/usr/bin/env bash
# Initialize local findings files in a project clone.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_NAME="$(basename "${PWD}")"
REMOTE_NAME=""

usage() {
    cat <<'USAGE'
Usage:
  scripts/init-project.sh [--name <project-name>] [--remote <private-git-url>]

Run from a project clone. The script copies the findings template into the
current directory without overwriting existing files, creates HANDOFF.md and
machines.md from templates, and runs the findings-repo smoke test.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --name)
            PROJECT_NAME="$2"; shift 2 ;;
        --remote)
            REMOTE_NAME="$2"; shift 2 ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            usage >&2
            exit 2 ;;
    esac
done

if [[ ! -d "${ROOT}/templates/findings-repo" ]]; then
    echo "ERROR: findings template missing: ${ROOT}/templates/findings-repo" >&2
    exit 2
fi

echo "==> Initializing findings files for ${PROJECT_NAME}"
rsync -a --ignore-existing "${ROOT}/templates/findings-repo/" ./
cp -n HANDOFF.md.template HANDOFF.md
cp -n machines.md.template machines.md
mkdir -p targets findings/analysis findings/candidates findings/reports artifacts tools/custom

if [[ -n "${REMOTE_NAME}" ]]; then
    echo "==> Setting git origin to ${REMOTE_NAME}"
    git remote set-url origin "${REMOTE_NAME}"
fi

echo "==> Running findings template smoke"
bash scripts/smoke-findings-repo.sh

cat <<EOF

OK - project initialized.

Next:
  1. Fill in LAB_SAFETY.md and machines.md.
  2. Open this folder in Cursor.
  3. Start intake:
     python3 scripts/start-target.py \"/Applications/<App Name>.app\" --pass-id PASS-001
EOF
