#!/usr/bin/env python3
"""Initialize project state from a macOS app bundle, framework, installer, or binary.

Thin CLI shim. The implementation lives in the start_target/ package
next to this file. Re-exports a few symbols at module scope so existing
test files that load this script as a module via importlib continue to
work without modification.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from start_target.cli import (  # noqa: E402
    IntakeResult,
    main,
    parse_args,
    start_target,
)
from start_target.inventory import IntakeError  # noqa: E402

# Re-exports for tests that load this script as a module via importlib.
from start_target.classify import (  # noqa: E402,F401
    maturity_coverage_gaps,
    surface_maturity_map,
)
from start_target.signing import (  # noqa: E402,F401
    apply_codesign_evidence,
    parse_dyld_dependencies,
)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
