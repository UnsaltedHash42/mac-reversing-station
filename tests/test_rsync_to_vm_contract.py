import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts/rsync-to-vm.sh"
TEMPLATE = REPO / "templates/findings-repo"


class TestRsyncToVmContract(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.tmp = Path(self.tmpdir.name)
        self.project = self.tmp / "project"
        shutil.copytree(TEMPLATE, self.project)
        (self.project / "targets").mkdir()
        (self.project / "targets/tool").write_text("fixture", encoding="utf-8")

    def write_fake_tool(self, name: str, body: str) -> None:
        fake_bin = self.tmp / "bin"
        fake_bin.mkdir(exist_ok=True)
        tool = fake_bin / name
        tool.write_text(body, encoding="utf-8")
        tool.chmod(tool.stat().st_mode | stat.S_IXUSR)

    def run_script(self, *args: str, ssh_ok: bool = True) -> subprocess.CompletedProcess[str]:
        ssh_body = "#!/usr/bin/env bash\n"
        if ssh_ok:
            ssh_body += "exit 0\n"
        else:
            ssh_body += "exit 1\n"
        self.write_fake_tool("ssh", ssh_body)
        self.write_fake_tool("rsync", "#!/usr/bin/env bash\nexit 0\n")

        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{self.tmp / 'bin'}:{env['PATH']}",
                "MACRE_MACHINE": "lab-host",
                "MACRE_REMOTE_TARGETS": "/Remote/Targets",
                "MACRE_PROJECT": "project",
            }
        )
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            cwd=str(self.project),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_record_mode_writes_remote_path_after_successful_sync(self) -> None:
        proc = self.run_script("--record", "example", "targets/")

        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        corpus = (self.project / "CORPUS.md").read_text(encoding="utf-8")
        self.assertIn("| example | targets | lab-host:/Remote/Targets/project |", corpus)

        second = self.run_script("--record", "example", "targets/")
        self.assertEqual(second.returncode, 0, msg=second.stdout + second.stderr)
        corpus = (self.project / "CORPUS.md").read_text(encoding="utf-8")
        self.assertEqual(corpus.count("| example | targets | lab-host:/Remote/Targets/project |"), 1)

    def test_default_sync_does_not_modify_corpus(self) -> None:
        proc = self.run_script("targets/")

        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        corpus = (self.project / "CORPUS.md").read_text(encoding="utf-8")
        self.assertNotIn("lab-host:/Remote/Targets/project", corpus)

    def test_unreachable_lab_host_fails_before_recording_mapping(self) -> None:
        proc = self.run_script("--record", "example", "targets/", ssh_ok=False)

        self.assertEqual(proc.returncode, 3, msg=proc.stdout + proc.stderr)
        corpus = (self.project / "CORPUS.md").read_text(encoding="utf-8")
        self.assertNotIn("lab-host:/Remote/Targets/project", corpus)

    def test_record_requires_target_id(self) -> None:
        proc = self.run_script("--record")

        self.assertEqual(proc.returncode, 2, msg=proc.stdout + proc.stderr)
        self.assertIn("--record requires a target id", proc.stderr)

    def test_missing_source_directory_fails(self) -> None:
        proc = self.run_script("missing-targets/")

        self.assertEqual(proc.returncode, 2, msg=proc.stdout + proc.stderr)
        self.assertIn("missing-targets/ does not exist", proc.stderr)


if __name__ == "__main__":
    unittest.main()
