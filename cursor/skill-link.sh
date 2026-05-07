#!/usr/bin/env bash
# Idempotently symlink every Skills/offensive-macos-* directory under
# ~/.cursor/skills/ so Cursor auto-considers them on every session.
#
# Prints one line per skill: linked | already-linked | orphaned
# ("orphaned" = exists in ~/.cursor/skills/ but no longer in Skills/).
#
# Safe to re-run. Never deletes anything — orphans are only reported.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILLS_SRC="${REPO_ROOT}/Skills"
SKILLS_DST="${HOME}/.cursor/skills"

if [[ ! -d "${SKILLS_SRC}" ]]; then
    echo "ERROR: ${SKILLS_SRC} does not exist" >&2
    exit 2
fi

mkdir -p "${SKILLS_DST}"

# Pass 1: link every canonical skill into ~/.cursor/skills/.
for skill_dir in "${SKILLS_SRC}"/offensive-macos-*; do
    [[ -d "${skill_dir}" ]] || continue
    name="$(basename "${skill_dir}")"
    target="${SKILLS_DST}/${name}"

    if [[ -L "${target}" ]]; then
        current="$(readlink "${target}")"
        if [[ "${current}" == "${skill_dir}" ]]; then
            printf 'already-linked   %s\n' "${name}"
            continue
        fi
        # symlink points elsewhere — update it
        ln -sfn "${skill_dir}" "${target}"
        printf 'relinked         %s (was -> %s)\n' "${name}" "${current}"
    elif [[ -e "${target}" ]]; then
        printf 'SKIPPED (not a symlink, refusing to overwrite) %s\n' "${name}" >&2
        continue
    else
        ln -s "${skill_dir}" "${target}"
        printf 'linked           %s\n' "${name}"
    fi
done

# Pass 2: report orphans (symlinks in ~/.cursor/skills/ whose source is gone).
for target in "${SKILLS_DST}"/offensive-macos-*; do
    [[ -L "${target}" ]] || continue
    if [[ ! -d "${target}" ]]; then
        printf 'orphaned         %s (target missing)\n' "$(basename "${target}")"
    fi
done
