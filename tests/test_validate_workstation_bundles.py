import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


class TestWorkstationBundleValidator(unittest.TestCase):
    def test_default_invocation_succeeds(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(REPO / "scripts/validate_workstation_bundles.py")],
            cwd=str(REPO),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)

    def test_flags_detect_missing_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            doc = tmp / "skill-bundles.md"
            doc.write_text("- `Skills/offensive-does-not-exist`\n", encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(REPO / "scripts/validate_workstation_bundles.py"),
                    "--root",
                    str(tmp),
                    "--doc",
                    str(doc),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("Skills/offensive-does-not-exist", proc.stderr)


if __name__ == "__main__":
    unittest.main()
