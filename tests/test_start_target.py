import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from plistlib import dump


REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts/start-target.py"
TEMPLATE = REPO / "templates/findings-repo"


class TestStartTarget(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.tmp = Path(self.tmpdir.name)
        self.project = self.tmp / "project"
        shutil.copytree(TEMPLATE, self.project)

    def run_script(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args, "--project-root", str(self.project)],
            cwd=str(REPO),
            capture_output=True,
            text=True,
            check=False,
        )

    def make_app(self) -> Path:
        app = self.tmp / "Example.app"
        contents = app / "Contents"
        macos = contents / "MacOS"
        xpc = contents / "XPCServices/com.example.worker.xpc/Contents"
        helper_tools = contents / "Library/HelperTools"

        macos.mkdir(parents=True)
        xpc.joinpath("MacOS").mkdir(parents=True)
        helper_tools.mkdir(parents=True)

        with (contents / "Info.plist").open("wb") as fh:
            dump(
                {
                    "CFBundleIdentifier": "com.example.Example",
                    "CFBundleShortVersionString": "1.2.3",
                    "CFBundleVersion": "123",
                    "CFBundleExecutable": "Example",
                    "NSCameraUsageDescription": "fixture",
                },
                fh,
            )
        with (xpc / "Info.plist").open("wb") as fh:
            dump(
                {
                    "CFBundleIdentifier": "com.example.worker",
                    "CFBundleExecutable": "Worker",
                },
                fh,
            )

        for executable in [
            macos / "Example",
            xpc / "MacOS/Worker",
            helper_tools / "com.example.helper",
        ]:
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(executable.stat().st_mode | 0o111)

        return app

    def test_app_bundle_intake_copies_inventories_and_updates_corpus(self) -> None:
        app = self.make_app()

        proc = self.run_script(str(app), "--pass-id", "PASS-001")

        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        copied_app = self.project / "targets/Example.app"
        self.assertTrue(copied_app.is_dir())
        (app / "Contents/MacOS/Example").write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")

        target_map = self.project / "findings/analysis/PASS-001-example-target-map.json"
        data = json.loads(target_map.read_text(encoding="utf-8"))
        self.assertEqual(data["target"]["kind"], "app-bundle")
        self.assertEqual(data["bundle"]["identifier"], "com.example.Example")
        self.assertIn("privileged helpers / updaters", data["classification"]["family_labels"])
        self.assertIn("TCC-heavy consumer apps", data["classification"]["family_labels"])
        self.assertTrue(any(component["kind"] == "xpc-service" for component in data["components"]))
        self.assertTrue(any(component["kind"] == "helper-tool" for component in data["components"]))
        self.assertFalse(
            any(
                component["path"] == "Contents/XPCServices/com.example.worker.xpc/Contents/MacOS/Worker"
                for component in data["components"]
            )
        )

        corpus = (self.project / "CORPUS.md").read_text(encoding="utf-8")
        self.assertIn("| PASS-001 |", corpus)
        self.assertIn("| example | Example.app | 1.2.3 (123) |", corpus)
        self.assertIn("| example | com.example.worker.xpc | xpc-service |", corpus)
        self.assertIn("| example | PASS-001 | privacy-permissions, privileged-helper-tools, xpc-services |", corpus)
        self.assertIn("| example | privileged helpers / updaters, TCC-heavy consumer apps | initial |", corpus)
        self.assertIn("| PASS-001 | Review intake inventory for Example.app |", corpus)

        second = self.run_script(str(app), "--pass-id", "PASS-001")
        self.assertEqual(second.returncode, 0, msg=second.stdout + second.stderr)
        self.assertEqual(
            (copied_app / "Contents/MacOS/Example").read_text(encoding="utf-8"),
            "#!/bin/sh\nexit 7\n",
        )
        corpus = (self.project / "CORPUS.md").read_text(encoding="utf-8")
        self.assertEqual(
            corpus.count("| PASS-001 | | privileged helpers / updaters, TCC-heavy consumer apps |"),
            1,
        )
        self.assertEqual(corpus.count("| example | Example.app |"), 1)
        self.assertEqual(corpus.count("| example | com.example.worker.xpc | xpc-service |"), 1)

    def test_bare_binary_intake_without_bundle_metadata(self) -> None:
        binary = self.tmp / "tool"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(binary.stat().st_mode | 0o111)

        proc = self.run_script(str(binary), "--pass-id", "PASS-002")

        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertTrue((self.project / "targets/tool").is_file())
        data = json.loads(
            (self.project / "findings/analysis/PASS-002-tool-target-map.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(data["target"]["kind"], "binary")
        self.assertEqual(data["bundle"], {})

    def test_no_copy_and_explicit_target_id_reference_original_path(self) -> None:
        binary = self.tmp / "odd name"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(binary.stat().st_mode | 0o111)

        proc = self.run_script(str(binary), "--pass-id", "PASS-003", "--target-id", "custom", "--no-copy")

        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertFalse((self.project / "targets/odd name").exists())
        data = json.loads(
            (self.project / "findings/analysis/PASS-003-custom-target-map.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(data["target"]["id"], "custom")
        self.assertEqual(data["target"]["local_path"], str(binary.resolve()))

    def test_missing_target_fails_without_partial_corpus_update(self) -> None:
        proc = self.run_script(str(self.tmp / "missing.app"), "--pass-id", "PASS-404")

        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("target path does not exist", proc.stderr)
        corpus = (self.project / "CORPUS.md").read_text(encoding="utf-8")
        self.assertNotIn("PASS-404", corpus)


if __name__ == "__main__":
    unittest.main()
