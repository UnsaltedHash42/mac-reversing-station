"""Tests for scripts/triage.py."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
TRIAGE = REPO / "scripts" / "triage.py"


def run(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TRIAGE), *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )


class TestTriage(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.addCleanup(self.tmpdir.cleanup)

    def _create_basic(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        args = [
            "create",
            "--pass-id", overrides.get("pass_id", "PASS-001"),
            "--target", overrides.get("target", "T-001"),
            "--title", overrides.get("title", "test candidate"),
            "--vuln-class", overrides.get("vuln_class", "wrong-door"),
            "--severity", overrides.get("severity", "medium"),
            "--primary-artifact", overrides.get("primary_artifact", "findings/analysis/x.tsv"),
        ]
        for k in ("anchor_tier", "anchor_kind", "anchor_name", "anchor_address", "id", "status"):
            if k in overrides:
                args.extend([f"--{k.replace('_', '-')}", overrides[k]])
        return run(*args, cwd=self.root)

    def test_create_writes_file_with_required_fields(self) -> None:
        result = self._create_basic()
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        path = self.root / "findings" / "candidates" / "C-001.json"
        self.assertTrue(path.exists())
        data = json.loads(path.read_text())
        self.assertEqual(data["id"], "C-001")
        self.assertEqual(data["status"], "scan-hit")
        self.assertEqual(data["pass_id"], "PASS-001")
        self.assertEqual(data["target_id"], "T-001")
        self.assertEqual(len(data["history"]), 1)
        self.assertEqual(data["history"][0]["status"], "scan-hit")

    def test_next_id_skips_existing(self) -> None:
        self._create_basic()
        self._create_basic(title="another")
        path = self.root / "findings" / "candidates" / "C-002.json"
        self.assertTrue(path.exists())

    def test_explicit_id_used_when_provided(self) -> None:
        self._create_basic(id="C-042")
        self.assertTrue((self.root / "findings" / "candidates" / "C-042.json").exists())

    def test_create_rejects_closed_without_reason(self) -> None:
        result = self._create_basic(status="closed")
        self.assertEqual(result.returncode, 2)
        self.assertIn("closure_reason", result.stderr)

    def test_transition_records_history_and_evidence(self) -> None:
        self._create_basic()
        result = run(
            "transition", "C-001", "escalated",
            "--evidence-path", "artifacts/x.lldb.log",
            "--evidence-kind", "lldb_transcript",
            "--binary-sha256", "deadbeef",
            cwd=self.root,
        )
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        data = json.loads((self.root / "findings/candidates/C-001.json").read_text())
        self.assertEqual(data["status"], "escalated")
        self.assertEqual(len(data["history"]), 2)
        self.assertEqual(len(data["evidence"]), 1)
        self.assertEqual(data["evidence"][0]["binary_sha256"], "deadbeef")

    def test_disallowed_transition_blocked(self) -> None:
        self._create_basic()
        result = run("transition", "C-001", "confirmed", cwd=self.root)
        self.assertEqual(result.returncode, 2)
        self.assertIn("not allowed", result.stderr)

    def test_close_requires_reason(self) -> None:
        self._create_basic()
        run("transition", "C-001", "escalated", cwd=self.root)
        result = run("transition", "C-001", "closed", cwd=self.root)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--reason", result.stderr)

    def test_terminal_closed_blocks_further_transition(self) -> None:
        self._create_basic()
        run("transition", "C-001", "closed", "--reason", "expected behavior",
            cwd=self.root)
        result = run("transition", "C-001", "scan-hit", cwd=self.root)
        self.assertEqual(result.returncode, 2)
        self.assertIn("terminal", result.stderr)

    def test_validate_passes_for_well_formed_dir(self) -> None:
        self._create_basic()
        self._create_basic(title="another")
        result = run("validate", cwd=self.root)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

    def test_validate_catches_missing_required_field(self) -> None:
        self._create_basic()
        path = self.root / "findings/candidates/C-001.json"
        data = json.loads(path.read_text())
        del data["title"]
        path.write_text(json.dumps(data))
        result = run("validate", cwd=self.root)
        self.assertEqual(result.returncode, 1)
        self.assertIn("title", result.stderr)

    def test_render_writes_index(self) -> None:
        self._create_basic()
        run("transition", "C-001", "escalated", cwd=self.root)
        result = run("render", cwd=self.root)
        self.assertEqual(result.returncode, 0)
        index = (self.root / "INDEX.md").read_text()
        self.assertIn("| C-001 |", index)
        self.assertIn("escalated", index)
        self.assertIn("Status values", index)

    def test_list_filters_by_status(self) -> None:
        self._create_basic()
        self._create_basic(title="b")
        run("transition", "C-002", "closed", "--reason", "ok", cwd=self.root)
        result = run("list", "--status", "closed", cwd=self.root)
        self.assertIn("C-002", result.stdout)
        self.assertNotIn("C-001", result.stdout)


if __name__ == "__main__":
    unittest.main()
