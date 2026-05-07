import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts/configure-cursor-mcp.py"


class TestConfigureCursorMcp(unittest.TestCase):
    def test_writes_and_preserves_existing_servers(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / "mcp.json"
            original = json.dumps({"mcpServers": {"existing": {"command": "true", "args": [], "env": {}}}})
            config.write_text(
                original,
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--host",
                    "my-lab",
                    "--remote-home",
                    "/Users/reuser",
                    "--config",
                    str(config),
                ],
                cwd=str(REPO),
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
            data = json.loads(config.read_text(encoding="utf-8"))
            backup = config.with_suffix(".json.bak")
            self.assertTrue(backup.is_file())
            self.assertEqual(backup.read_text(encoding="utf-8"), original)
            self.assertIn("existing", data["mcpServers"])
            self.assertEqual(data["mcpServers"]["ghidra-mcp"]["args"][-1], "/Users/reuser/bin/ghidra-mcp-launch")
            self.assertEqual(data["mcpServers"]["macre-vm-mcp"]["args"][4], "my-lab")
            self.assertEqual(data["mcpServers"]["macre-vm-mcp"]["args"][-2:], ["-m", "macre_vm_mcp"])

            second = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--host",
                    "my-lab",
                    "--remote-home",
                    "/Users/reuser",
                    "--config",
                    str(config),
                ],
                cwd=str(REPO),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(second.returncode, 0, msg=second.stdout + second.stderr)
            self.assertIn("already up to date", second.stdout)

    def test_dry_run_does_not_write_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / "mcp.json"

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--host",
                    "my-lab",
                    "--remote-home",
                    "/Users/reuser",
                    "--config",
                    str(config),
                    "--dry-run",
                ],
                cwd=str(REPO),
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
            self.assertFalse(config.exists())
            data = json.loads(proc.stdout)
            self.assertIn("ghidra-mcp", data["mcpServers"])

    def test_invalid_existing_json_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / "mcp.json"
            config.write_text("{not-json", encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--host",
                    "my-lab",
                    "--remote-home",
                    "/Users/reuser",
                    "--config",
                    str(config),
                ],
                cwd=str(REPO),
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("invalid JSON", proc.stderr + proc.stdout)

    def test_no_backup_flag_skips_backup_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / "mcp.json"
            config.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--host",
                    "my-lab",
                    "--remote-home",
                    "/Users/reuser",
                    "--config",
                    str(config),
                    "--no-backup",
                ],
                cwd=str(REPO),
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
            self.assertFalse(config.with_suffix(".json.bak").exists())


if __name__ == "__main__":
    unittest.main()
