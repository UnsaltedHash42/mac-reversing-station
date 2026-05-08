"""Target-intake package. The CLI entry point lives in start_target.cli."""

from .cli import IntakeError, IntakeResult, main, parse_args, start_target
from .signing import (
    apply_codesign_evidence,
    parse_dyld_dependencies,
)
from .classify import (
    maturity_coverage_gaps,
    surface_maturity_map,
)

__all__ = [
    "IntakeError",
    "IntakeResult",
    "main",
    "parse_args",
    "start_target",
    "apply_codesign_evidence",
    "parse_dyld_dependencies",
    "maturity_coverage_gaps",
    "surface_maturity_map",
]
