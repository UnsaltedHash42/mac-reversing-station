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
        dossier = self.project / "findings/analysis/PASS-001-example-dossier.json"
        dossier_data = json.loads(dossier.read_text(encoding="utf-8"))
        self.assertEqual(data["target"]["kind"], "app-bundle")
        self.assertEqual(data["bundle"]["identifier"], "com.example.Example")
        self.assertEqual(data["dossier_path"], "findings/analysis/PASS-001-example-dossier.json")
        self.assertIn("bundle-dossier", data["decision_support"]["recommended_recipes"])
        self.assertIn("scan_xpc_client_validation.py", data["decision_support"]["recommended_ghidra_scripts"])
        self.assertEqual(dossier_data["ledger"]["anchor_id"], "PASS-001:example")
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
        self.assertIn(
            "| example | PASS-001 | privacy-permissions, privileged-helper-tools, xpc-services |",
            corpus,
        )
        self.assertIn("| example | PASS-001 | `findings/analysis/PASS-001-example-dossier.json` |", corpus)
        self.assertIn("| PASS-001:example | example | `findings/analysis/PASS-001-example-dossier.json` |", corpus)
        self.assertIn("| example | privileged helpers / updaters, TCC-heavy consumer apps | initial |", corpus)
        self.assertIn("| PASS-001 | Scryer review for Example.app |", corpus)

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
        self.assertEqual(corpus.count("| example | PASS-001 | `findings/analysis/PASS-001-example-dossier.json` |"), 1)

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
        self.assertIn("inventory-first-manual-routing", data["decision_support"]["recommended_recipes"])

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

    def test_source_metadata_records_correlation_without_copying_source(self) -> None:
        binary = self.tmp / "tool"
        source_root = self.tmp / "source"
        source_root.mkdir()
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(binary.stat().st_mode | 0o111)

        proc = self.run_script(
            str(binary),
            "--pass-id",
            "PASS-004",
            "--source-root",
            str(source_root),
            "--source-ref",
            "v1.0.0",
            "--source-url",
            "https://example.invalid/repo",
        )

        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        data = json.loads(
            (self.project / "findings/analysis/PASS-004-tool-target-map.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(data["source_correlation"]["confidence"], "pending-binary-correlation")
        self.assertIn("correlate-source-to-binary", data["decision_support"]["recommended_recipes"])
        corpus = (self.project / "CORPUS.md").read_text(encoding="utf-8")
        self.assertIn("| tool | v1.0.0 | pending-binary-correlation |", corpus)
        self.assertFalse((self.project / "targets/source").exists())

        second = self.run_script(
            str(binary),
            "--pass-id",
            "PASS-004",
            "--source-ref",
            "v1.0.1",
            "--source-url",
            "https://user:token@example.invalid/repo",
        )
        self.assertEqual(second.returncode, 0, msg=second.stdout + second.stderr)
        corpus = (self.project / "CORPUS.md").read_text(encoding="utf-8")
        self.assertIn("| tool | v1.0.1 | unverified |", corpus)
        self.assertNotIn("user:token", corpus)
        self.assertEqual(corpus.count("| tool | v1.0."), 1)

    def test_electron_bundle_detects_surface_pack_indicators(self) -> None:
        app = self.make_app()
        resources = app / "Contents/Resources"
        framework = app / "Contents/Frameworks/Electron Framework.framework"
        resources.mkdir()
        framework.mkdir(parents=True)
        (resources / "app.asar").write_text("fixture", encoding="utf-8")
        (resources / "package.json").write_text(
            json.dumps({"name": "electron-fixture", "version": "1.0.0", "main": "main.js"}),
            encoding="utf-8",
        )
        (resources / "preload.js").write_text("// fixture\n", encoding="utf-8")
        native_dir = resources / "app/node_modules/native"
        native_dir.mkdir(parents=True)
        (native_dir / "native.node").write_text("fixture", encoding="utf-8")

        proc = self.run_script(str(app), "--pass-id", "PASS-005")

        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        data = json.loads(
            (self.project / "findings/analysis/PASS-005-example-target-map.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertTrue(data["electron"]["is_electron"])
        self.assertIn("Contents/Resources/app.asar", data["electron"]["asar_archives"])
        self.assertIn("Contents/Resources/package.json", data["electron"]["package_json"])
        self.assertIn("Contents/Resources/preload.js", data["electron"]["preload_scripts"])
        self.assertIn("Contents/Resources/app/node_modules/native/native.node", data["electron"]["native_modules"])
        self.assertEqual(data["electron"]["package_metadata"]["name"], "electron-fixture")
        self.assertIn("electron-app", data["classification"]["surfaces"])
        self.assertIn("electron-native-modules", data["classification"]["surfaces"])
        self.assertIn("review-electron-ipc-and-packaging", data["decision_support"]["recommended_recipes"])

    def test_plain_package_json_does_not_create_electron_false_positive(self) -> None:
        app = self.make_app()
        resources = app / "Contents/Resources"
        resources.mkdir()
        (resources / "package.json").write_text(
            json.dumps({"name": "plain-fixture", "version": "1.0.0", "main": "index.js"}),
            encoding="utf-8",
        )

        proc = self.run_script(str(app), "--pass-id", "PASS-006")

        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        data = json.loads(
            (self.project / "findings/analysis/PASS-006-example-target-map.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(data["electron"]["is_electron"])
        self.assertNotIn("electron-app", data["classification"]["surfaces"])

    def test_symlinked_package_json_is_not_read_for_electron_metadata(self) -> None:
        app = self.make_app()
        resources = app / "Contents/Resources"
        resources.mkdir()
        outside = self.tmp / "outside-package.json"
        outside.write_text(json.dumps({"name": "electron-secret", "dependencies": {"electron": "*"}}), encoding="utf-8")
        (resources / "package.json").symlink_to(outside)

        proc = self.run_script(str(app), "--pass-id", "PASS-007")

        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        data = json.loads(
            (self.project / "findings/analysis/PASS-007-example-target-map.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(data["electron"]["package_metadata"])
        self.assertFalse(data["electron"]["is_electron"])

    def test_missing_target_fails_without_partial_corpus_update(self) -> None:
        proc = self.run_script(str(self.tmp / "missing.app"), "--pass-id", "PASS-404")

        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("target path does not exist", proc.stderr)
        corpus = (self.project / "CORPUS.md").read_text(encoding="utf-8")
        self.assertNotIn("PASS-404", corpus)


if __name__ == "__main__":
    unittest.main()
