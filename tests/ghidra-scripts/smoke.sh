#!/usr/bin/env bash
# Structural smoke test for Ghidra hunt scripts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="${ROOT}/ghidra-scripts"

python3 - <<'PY' "${SCRIPT_DIR}"
from __future__ import annotations

import ast
import sys
from pathlib import Path

script_dir = Path(sys.argv[1])
expected_headers = {
    "scan_wrong_door.py": "daemon\tlisteners\tent_refs\tshould_accept_impls\taudit_token_uses\tevidence",
    "scan_defaults_bypass.py": "target\ttype\tdomains\tkeys\tbypass_strings\tconfidence\tevidence",
    "scan_catalyst_porting_gap.py": "target\tcatalyst_refs\tplatform_checks\tentitlement_refs\tbypass_refs\tconfidence\tevidence",
    "scan_flags_zero.py": "target\tcode_sign_refs\tflags_zero_refs\tamfi_refs\tconfidence\tevidence",
    "dump_xpc_listeners.py": "target\tmach_services\tlistener_delegate_impls\txpc_strings\tevidence",
    "scan_xpc_client_validation.py": "target\tmach_services\tshould_accept_refs\taudit_token_refs\tweak_identity_refs\tteam_id_refs\tconfidence\tevidence",
    "scan_privileged_helper_surface.py": "target\thelpers\tlaunchd_refs\tauthz_refs\tinstall_refs\tprivileged_ops\tconfidence\tevidence",
    "scan_tcc_prompt_surface.py": "target\ttcc_refs\tprompt_refs\tbundle_identity_refs\tapple_event_refs\tprivacy_services\tconfidence\tevidence",
    "scan_persistent_authorization.py": "target\tbookmark_refs\tkeychain_refs\tcontainer_store_refs\tsandbox_refs\tfile_access_refs\tconfidence\tevidence",
}

errors: list[str] = []
for name, header in expected_headers.items():
    path = script_dir / name
    if not path.is_file():
        errors.append(f"missing {path}")
        continue
    text = path.read_text(encoding="utf-8")
    try:
        ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        errors.append(f"{name}: syntax error: {exc}")
    if header not in text:
        errors.append(f"{name}: missing expected TSV header")

readme = script_dir / "README.md"
if not readme.is_file():
    errors.append("missing ghidra-scripts/README.md")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    raise SystemExit(1)

print(f"OK - {len(expected_headers)} Ghidra hunt scripts have valid syntax and TSV headers.")
PY
