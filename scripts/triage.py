#!/usr/bin/env python3
"""Candidate lifecycle helper for the macOS reversing studio.

Each candidate lives in `findings/candidates/C-NNN.json`. This script
creates new candidates, transitions them through the state machine
(see `docs/triage-states.md`), validates schemas, and re-renders
`INDEX.md` from the on-disk candidate files.

Run from the project clone root.

Subcommands:

    triage.py create
        --pass-id PASS-NNN
        --target TARGET-ID
        --title 'short title'
        --vuln-class <ontology class>
        --severity high|medium|low|info
        --primary-artifact <path>
        [--anchor-tier A|B|C --anchor-kind ... --anchor-name ... --anchor-address 0x...]

    triage.py transition C-NNN <status>
        [--reason 'closure rationale']
        [--evidence-path <path> --evidence-kind decompilation|lldb_transcript|...]
        [--binary-sha256 <hex>]
        [--next-action 'one sentence']

    triage.py list [--status STATUS] [--pass PASS-NNN] [--target TARGET-ID]

    triage.py validate [PATH]         # validate one file, or all if omitted
    triage.py render                  # regenerate INDEX.md from candidate files
    triage.py show C-NNN              # print one candidate as readable JSON

    triage.py import-tsv <path.tsv>
        --pass-id PASS-NNN
        [--target TARGET-ID]
        [--vuln-class <class>]
        [--severity medium]
        [--include-tier-b]
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any


CANDIDATES_DIR = Path("findings") / "candidates"
INDEX_PATH = Path("INDEX.md")


# --------------------------------------------------------------------------
# Schema + state machine
# --------------------------------------------------------------------------

VALID_STATUSES = (
    "hypothesis",
    "scan-hit",
    "hold",
    "blocked",
    "escalated",
    "reproducing",
    "confirmed",
    "report-ready",
    "reported",
    "closed",
)

# Allowed transitions. `closed` accepts entry from any state but only
# requires a rationale. `reported` is terminal but can be reopened by
# editing the file by hand if the state machine is wrong for the case.
TRANSITIONS = {
    "hypothesis":   {"scan-hit", "hold", "closed", "blocked"},
    "scan-hit":     {"escalated", "hold", "closed", "blocked"},
    "hold":         {"scan-hit", "escalated", "closed", "blocked"},
    "blocked":      {"scan-hit", "escalated", "closed"},
    "escalated":    {"reproducing", "hold", "closed", "blocked"},
    "reproducing":  {"confirmed", "hold", "closed", "blocked"},
    "confirmed":    {"report-ready", "closed"},
    "report-ready": {"reported", "closed"},
    "reported":     {"closed"},
    "closed":       set(),  # terminal; reopen by editing the file
}

REQUIRED_TOP_FIELDS = (
    "id", "pass_id", "target_id", "title", "vuln_class",
    "status", "severity", "primary_artifact",
)


# --------------------------------------------------------------------------
# IO helpers
# --------------------------------------------------------------------------

def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def candidates_dir(create: bool = False) -> Path:
    if create:
        CANDIDATES_DIR.mkdir(parents=True, exist_ok=True)
    return CANDIDATES_DIR


def load_candidate(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def save_candidate(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=2, sort_keys=False) + "\n"
    path.write_text(text, encoding="utf-8")


def candidate_path(candidate_id: str) -> Path:
    if not re.fullmatch(r"C-\d{3,}", candidate_id):
        raise SystemExit(f"ERROR: candidate id must be C-NNN, got {candidate_id!r}")
    return candidates_dir() / f"{candidate_id}.json"


def list_candidate_files() -> list[Path]:
    if not CANDIDATES_DIR.is_dir():
        return []
    return sorted(CANDIDATES_DIR.glob("C-*.json"))


def next_candidate_id() -> str:
    used = set()
    for path in list_candidate_files():
        match = re.match(r"C-(\d+)\.json", path.name)
        if match:
            used.add(int(match.group(1)))
    n = 1
    while n in used:
        n += 1
    return "C-%03d" % n


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

def validate_one(data: dict[str, Any], origin: str = "<inline>") -> list[str]:
    errors: list[str] = []
    for field in REQUIRED_TOP_FIELDS:
        if field not in data:
            errors.append(f"{origin}: missing field {field!r}")
    if "id" in data and not re.fullmatch(r"C-\d{3,}", str(data["id"])):
        errors.append(f"{origin}: id must match C-NNN")
    if data.get("status") not in VALID_STATUSES:
        errors.append(f"{origin}: status {data.get('status')!r} not in {VALID_STATUSES}")
    if data.get("severity") not in ("info", "low", "medium", "high", "critical"):
        errors.append(f"{origin}: severity {data.get('severity')!r} invalid")
    if "history" in data and not isinstance(data["history"], list):
        errors.append(f"{origin}: history must be a list")
    if "evidence" in data and not isinstance(data["evidence"], list):
        errors.append(f"{origin}: evidence must be a list")
    anchor = data.get("anchor")
    if anchor is not None:
        if not isinstance(anchor, dict):
            errors.append(f"{origin}: anchor must be an object")
        else:
            tier = anchor.get("tier")
            if tier is not None and tier not in ("A", "B", "C"):
                errors.append(f"{origin}: anchor.tier {tier!r} not A/B/C")
    if data.get("status") == "closed":
        if not (data.get("closure_reason") or "").strip():
            errors.append(f"{origin}: closed candidates require closure_reason")
    return errors


def cmd_validate(args: argparse.Namespace) -> int:
    paths = [Path(args.path)] if args.path else list_candidate_files()
    if not paths:
        print("(no candidate files to validate)")
        return 0
    all_errors: list[str] = []
    for path in paths:
        try:
            data = load_candidate(path)
        except json.JSONDecodeError as exc:
            all_errors.append(f"{path}: invalid JSON: {exc}")
            continue
        all_errors.extend(validate_one(data, origin=str(path)))
    if all_errors:
        for err in all_errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1
    print(f"OK - {len(paths)} candidate file(s) valid.")
    return 0


# --------------------------------------------------------------------------
# Create
# --------------------------------------------------------------------------

def cmd_create(args: argparse.Namespace) -> int:
    candidates_dir(create=True)
    cid = args.id or next_candidate_id()
    path = candidate_path(cid)
    if path.exists():
        print(f"ERROR: {path} already exists", file=sys.stderr)
        return 2

    anchor: dict[str, Any] | None = None
    if any([args.anchor_tier, args.anchor_kind, args.anchor_name, args.anchor_address]):
        anchor = {
            "tier": args.anchor_tier,
            "kind": args.anchor_kind,
            "name": args.anchor_name,
            "address": args.anchor_address or "-",
        }

    data: dict[str, Any] = {
        "id": cid,
        "pass_id": args.pass_id,
        "target_id": args.target,
        "title": args.title,
        "vuln_class": args.vuln_class,
        "status": "scan-hit" if args.status is None else args.status,
        "severity": args.severity,
        "primary_artifact": args.primary_artifact,
        "anchor": anchor,
        "evidence": [],
        "history": [{"status": "scan-hit" if args.status is None else args.status,
                     "at": now_iso()}],
        "next_action": args.next_action or "confirm in lldb",
    }

    errors = validate_one(data, origin=str(path))
    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 2

    save_candidate(path, data)
    print(f"created {path}")
    return 0


# --------------------------------------------------------------------------
# Transition
# --------------------------------------------------------------------------

def cmd_transition(args: argparse.Namespace) -> int:
    path = candidate_path(args.id)
    if not path.exists():
        print(f"ERROR: {path} not found", file=sys.stderr)
        return 2
    data = load_candidate(path)
    current = data.get("status")
    new = args.new_status

    if new not in VALID_STATUSES:
        print(f"ERROR: {new!r} is not a valid status", file=sys.stderr)
        return 2
    if new == current:
        print(f"ERROR: already in status {current!r}", file=sys.stderr)
        return 2
    allowed = TRANSITIONS.get(current, set())
    if new not in allowed:
        print(f"ERROR: {current!r} -> {new!r} is not allowed "
              f"(allowed: {sorted(allowed) or 'none (terminal)'})", file=sys.stderr)
        return 2

    if new == "closed" and not (args.reason or "").strip():
        print("ERROR: closing a candidate requires --reason", file=sys.stderr)
        return 2

    data["status"] = new
    if new == "closed":
        data["closure_reason"] = args.reason

    if args.evidence_path:
        evidence = data.setdefault("evidence", [])
        entry: dict[str, Any] = {
            "kind": args.evidence_kind or "note",
            "path": args.evidence_path,
            "added_at": now_iso(),
        }
        if args.binary_sha256:
            entry["binary_sha256"] = args.binary_sha256
        if args.reason:
            entry["note"] = args.reason
        evidence.append(entry)

    if args.next_action is not None:
        data["next_action"] = args.next_action

    history = data.setdefault("history", [])
    history.append({
        "status": new,
        "at": now_iso(),
        **({"reason": args.reason} if args.reason else {}),
    })

    errors = validate_one(data, origin=str(path))
    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 2

    save_candidate(path, data)
    print(f"{args.id}: {current} -> {new}")
    return 0


# --------------------------------------------------------------------------
# List / show
# --------------------------------------------------------------------------

def cmd_list(args: argparse.Namespace) -> int:
    rows = []
    for path in list_candidate_files():
        try:
            data = load_candidate(path)
        except json.JSONDecodeError:
            continue
        if args.status and data.get("status") != args.status:
            continue
        if args.pass_id and data.get("pass_id") != args.pass_id:
            continue
        if args.target and data.get("target_id") != args.target:
            continue
        rows.append(data)
    if not rows:
        print("(no candidates)")
        return 0
    print("%-8s %-12s %-10s %-22s %-9s %-9s %s" %
          ("ID", "PASS", "TARGET", "CLASS", "STATUS", "SEVERITY", "TITLE"))
    for d in rows:
        print("%-8s %-12s %-10s %-22s %-9s %-9s %s" % (
            d.get("id", ""), d.get("pass_id", ""), d.get("target_id", ""),
            d.get("vuln_class", ""), d.get("status", ""),
            d.get("severity", ""), d.get("title", ""),
        ))
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    path = candidate_path(args.id)
    if not path.exists():
        print(f"ERROR: {path} not found", file=sys.stderr)
        return 2
    data = load_candidate(path)
    print(json.dumps(data, indent=2))
    return 0


# --------------------------------------------------------------------------
# Render INDEX.md
# --------------------------------------------------------------------------

INDEX_HEADER = """# Findings Index

Generated by `scripts/triage.py render` from `findings/candidates/*.json`.
Edit candidates by running `scripts/triage.py transition <id> <status>`,
not by editing this file. Manual edits to this section will be overwritten.

| ID | Pass ID | Target | Title | Class | Status | Severity | Primary Artifact | Next Action |
|----|---------|--------|-------|-------|--------|----------|------------------|-------------|
"""

INDEX_FOOTER = """
## Status values

- `hypothesis` -- plausible class match, no evidence yet.
- `scan-hit` -- static / metadata sweep produced this candidate row.
- `hold` -- worth revisiting, not the current pass priority.
- `blocked` -- cannot proceed until a lab / auth / tool issue is fixed.
- `escalated` -- promoted from triage to focused deep dive.
- `reproducing` -- active dynamic confirmation or PoC minimization.
- `confirmed` -- lab reproduction and root cause understood.
- `report-ready` -- evidence package is ready for `REPORTING.md`.
- `reported` -- sent to vendor / internal team / Apple.
- `closed` -- closed with rationale. Closures count in `METRICS.md`.

## Closure rationale

Every `closed` row must carry a `closure_reason` in its candidate file.
Common rationales:

- Expected behavior.
- Already gated by authorization.
- No reachability from the attacker model.
- Duplicate of another candidate.
- Tooling false positive.
- Out of scope for the current authorization.
"""


def cmd_render(args: argparse.Namespace) -> int:
    rows = []
    for path in list_candidate_files():
        try:
            data = load_candidate(path)
        except json.JSONDecodeError:
            continue
        rows.append(data)
    rows.sort(key=lambda d: d.get("id", ""))

    body_lines: list[str] = [INDEX_HEADER]
    for d in rows:
        body_lines.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            d.get("id", ""), d.get("pass_id", ""), d.get("target_id", ""),
            (d.get("title") or "").replace("|", "\\|"),
            d.get("vuln_class", ""), d.get("status", ""), d.get("severity", ""),
            (d.get("primary_artifact") or "").replace("|", "\\|"),
            (d.get("next_action") or "").replace("|", "\\|"),
        ))
    body_lines.append(INDEX_FOOTER)

    INDEX_PATH.write_text("\n".join(body_lines) + "\n", encoding="utf-8")
    print(f"rendered {INDEX_PATH} ({len(rows)} candidate(s))")
    return 0


# --------------------------------------------------------------------------
# Import from Ghidra TSV
# --------------------------------------------------------------------------

def cmd_import_tsv(args: argparse.Namespace) -> int:
    """Import tier-A (and optionally B) rows from a Ghidra scan TSV as candidates."""
    tsv_path = Path(args.tsv)
    if not tsv_path.is_file():
        print(f"ERROR: {tsv_path} not found", file=sys.stderr)
        return 2

    lines = tsv_path.read_text(encoding="utf-8").strip().splitlines()
    if not lines:
        print("ERROR: empty TSV", file=sys.stderr)
        return 2

    header = lines[0].split("\t")
    expected = ["target", "tier", "anchor_kind", "name", "address", "evidence"]
    if header != expected:
        print(f"ERROR: unexpected header. Got: {header}", file=sys.stderr)
        print(f"Expected: {expected}", file=sys.stderr)
        return 2

    tiers_to_import = {"A"}
    if args.include_tier_b:
        tiers_to_import.add("B")

    candidates_dir(create=True)
    created = 0
    skipped = 0

    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) < 6:
            skipped += 1
            continue
        target, tier, anchor_kind, name, address, evidence = fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]

        if tier not in tiers_to_import:
            skipped += 1
            continue

        cid = next_candidate_id()
        title = f"{anchor_kind}: {name}" if name != "-" else anchor_kind
        if len(title) > 80:
            title = title[:77] + "..."

        data: dict[str, Any] = {
            "id": cid,
            "pass_id": args.pass_id,
            "target_id": args.target or target,
            "title": title,
            "vuln_class": args.vuln_class or _infer_vuln_class(anchor_kind),
            "status": "scan-hit",
            "severity": args.severity,
            "primary_artifact": str(tsv_path),
            "anchor": {
                "tier": tier,
                "kind": anchor_kind,
                "name": name,
                "address": address,
            },
            "evidence": [{
                "kind": "scan-tsv",
                "path": str(tsv_path),
                "added_at": now_iso(),
                "note": evidence,
            }],
            "history": [{"status": "scan-hit", "at": now_iso()}],
            "next_action": "decompile and verify",
        }

        errors = validate_one(data, origin=cid)
        if errors:
            for err in errors:
                print(f"WARN: {err} (skipping row)", file=sys.stderr)
            skipped += 1
            continue

        path = candidate_path(cid)
        save_candidate(path, data)
        print(f"  created {cid}: {title}")
        created += 1

    print(f"\nImported {created} candidate(s), skipped {skipped} row(s).")
    return 0


def _infer_vuln_class(anchor_kind: str) -> str:
    """Best-effort mapping from anchor_kind to ontology vuln class."""
    kind_lower = anchor_kind.lower()
    if "xpc" in kind_lower or "listener" in kind_lower or "mach_service" in kind_lower:
        return "xpc-client-validation"
    if "wrong_door" in kind_lower or "should_accept" in kind_lower:
        return "wrong-door"
    if "audit_token" in kind_lower or "sectask" in kind_lower:
        return "xpc-client-validation"
    if "defaults" in kind_lower or "cfprefs" in kind_lower or "nsuserdefaults" in kind_lower:
        return "defaults-bypass"
    if "privilege" in kind_lower or "smjobbless" in kind_lower or "auth" in kind_lower:
        return "privileged-helper-authz"
    if "es_" in kind_lower or "endpoint" in kind_lower:
        return "endpoint-security"
    if "tcc" in kind_lower or "privacy" in kind_lower:
        return "tcc-prompt"
    if "iokit" in kind_lower or "ioconnect" in kind_lower:
        return "iokit-userclient"
    if "dlopen" in kind_lower or "framework" in kind_lower:
        return "private-framework-hijack"
    if "url" in kind_lower or "scheme" in kind_lower:
        return "url-scheme-hijack"
    if "bookmark" in kind_lower or "keychain" in kind_lower or "sandbox" in kind_lower:
        return "persistent-authorization"
    if "exec" in kind_lower or "system" in kind_lower or "popen" in kind_lower:
        return "privileged-helper-authz"
    return "unclassified"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="triage.py", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_create = sub.add_parser("create", help="create a new candidate")
    p_create.add_argument("--id", help="explicit C-NNN id (default: next free)")
    p_create.add_argument("--pass-id", required=True)
    p_create.add_argument("--target", required=True)
    p_create.add_argument("--title", required=True)
    p_create.add_argument("--vuln-class", required=True,
                          help="e.g. wrong-door, defaults-bypass, tcc-prompt")
    p_create.add_argument("--severity", default="medium",
                          choices=["info", "low", "medium", "high", "critical"])
    p_create.add_argument("--primary-artifact", required=True,
                          help="path to the scan TSV / dossier / decompilation")
    p_create.add_argument("--status", choices=VALID_STATUSES,
                          help="initial status (default: scan-hit)")
    p_create.add_argument("--anchor-tier", choices=["A", "B", "C"])
    p_create.add_argument("--anchor-kind")
    p_create.add_argument("--anchor-name")
    p_create.add_argument("--anchor-address", default="-")
    p_create.add_argument("--next-action")
    p_create.set_defaults(func=cmd_create)

    p_trans = sub.add_parser("transition", help="transition a candidate to a new status")
    p_trans.add_argument("id")
    p_trans.add_argument("new_status", choices=VALID_STATUSES)
    p_trans.add_argument("--reason", help="rationale; required for closed")
    p_trans.add_argument("--evidence-path", help="path to add as evidence")
    p_trans.add_argument("--evidence-kind",
                          help="e.g. decompilation, lldb_transcript, dtrace_trace, note")
    p_trans.add_argument("--binary-sha256",
                          help="hash-pin the binary slice the evidence refers to")
    p_trans.add_argument("--next-action", help="next concrete step")
    p_trans.set_defaults(func=cmd_transition)

    p_list = sub.add_parser("list", help="list candidates with optional filters")
    p_list.add_argument("--status", choices=VALID_STATUSES)
    p_list.add_argument("--pass", dest="pass_id")
    p_list.add_argument("--target")
    p_list.set_defaults(func=cmd_list)

    p_val = sub.add_parser("validate", help="validate a candidate file (or all)")
    p_val.add_argument("path", nargs="?")
    p_val.set_defaults(func=cmd_validate)

    p_render = sub.add_parser("render", help="regenerate INDEX.md from candidate files")
    p_render.set_defaults(func=cmd_render)

    p_show = sub.add_parser("show", help="print one candidate as JSON")
    p_show.add_argument("id")
    p_show.set_defaults(func=cmd_show)

    p_import = sub.add_parser("import-tsv",
                              help="batch-create candidates from a Ghidra scan TSV")
    p_import.add_argument("tsv", help="path to a Ghidra scan TSV file")
    p_import.add_argument("--pass-id", required=True)
    p_import.add_argument("--target", help="override target_id (default: from TSV)")
    p_import.add_argument("--vuln-class", help="override vuln class (default: inferred from anchor_kind)")
    p_import.add_argument("--severity", default="medium",
                          choices=["info", "low", "medium", "high", "critical"])
    p_import.add_argument("--include-tier-b", action="store_true",
                          help="also import tier-B rows (default: tier-A only)")
    p_import.set_defaults(func=cmd_import_tsv)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
