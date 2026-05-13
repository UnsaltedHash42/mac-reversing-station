#!/usr/bin/env bash
# Install a `~/tools/skills` -> `~/tools/skillz` symlink so both path forms
# resolve to the same dev repo. Idempotent. Refuses to overwrite an existing
# non-symlink at the alias path.
#
# Why: operator-facing notes drifted between `tools/skills` and `tools/skillz`
# during PASS-001. The repo's canonical name is `skillz`; the alias preserves
# muscle memory without breaking anything else.
#
# Exit codes:
#   0  symlink already correct, or created successfully
#   1  alias path exists as a real directory or file (refused)
#   2  source path missing (run from a system that has the dev repo)

set -euo pipefail

SOURCE="$HOME/tools/skillz"
ALIAS="$HOME/tools/skills"

if [[ ! -d "$SOURCE" ]]; then
    echo "source missing: $SOURCE" >&2
    exit 2
fi

if [[ -L "$ALIAS" ]]; then
    CURRENT="$(readlink "$ALIAS")"
    if [[ "$CURRENT" == "$SOURCE" || "$CURRENT" == "skillz" ]]; then
        echo "[install-skills-symlink] alias already points at skillz; nothing to do"
        exit 0
    fi
    echo "alias is a symlink to '$CURRENT' — refusing to overwrite" >&2
    exit 1
fi

if [[ -e "$ALIAS" ]]; then
    echo "alias exists as a real directory or file: $ALIAS" >&2
    echo "  refusing to delete operator data; remove it manually if intended" >&2
    exit 1
fi

ln -s skillz "$ALIAS"
echo "[install-skills-symlink] created $ALIAS -> skillz"
