import importlib.util
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


def load_start_target_module():
    """Load scripts/start-target.py as a module so helper functions can be unit-tested.

    The script imports from a `start_target` package next to itself, so we
    register this loaded shim under a distinct name (`start_target_script`)
    to avoid colliding with the package in sys.modules.
    """
    sys.path.insert(0, str(SCRIPT.parent))
    spec = importlib.util.spec_from_file_location("start_target_script", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("start_target_script", module)
    spec.loader.exec_module(module)
    return module


start_target_module = load_start_target_module()


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
        self.assertEqual(dossier_data["scriptorium"]["anchor_id"], "PASS-001:example")
        self.assertEqual(dossier_data["scriptorium"]["chronicle"], "CHRONICLE.md")
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
        self.assertIn("| PASS-001 | Watch review for Example.app |", corpus)

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

    def test_bare_daemon_named_binary_classified_as_daemon(self) -> None:
        binary = self.tmp / "examplesd"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(binary.stat().st_mode | 0o111)

        proc = self.run_script(str(binary), "--pass-id", "PASS-100")

        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        data = json.loads(
            (self.project / "findings/analysis/PASS-100-examplesd-target-map.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(data["target"]["kind"], "daemon")
        self.assertIn("os-component", data["classification"]["surfaces"])
        self.assertIn("apple-os-components", data["classification"]["family_labels"])

    def test_apple_bundle_identifier_marks_apple_signed_and_os_component(self) -> None:
        app = self.tmp / "ExampleApple.app"
        contents = app / "Contents"
        macos = contents / "MacOS"
        macos.mkdir(parents=True)
        with (contents / "Info.plist").open("wb") as fh:
            dump(
                {
                    "CFBundleIdentifier": "com.apple.example",
                    "CFBundleExecutable": "ExampleApple",
                    "CFBundleShortVersionString": "1.0",
                },
                fh,
            )
        executable = macos / "ExampleApple"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(executable.stat().st_mode | 0o111)

        proc = self.run_script(str(app), "--pass-id", "PASS-101")

        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        data = json.loads(
            (self.project / "findings/analysis/PASS-101-exampleapple-target-map.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIn("apple-signed", data["classification"]["surfaces"])
        self.assertIn("os-component", data["classification"]["surfaces"])
        self.assertIn("apple-os-components", data["classification"]["family_labels"])
        self.assertTrue(data["os_component"]["apple_signed"])
        self.assertEqual(data["os_component"]["authority"], "bundle-identifier-heuristic")

    def test_system_extension_inside_app_bundle_records_component_and_surface(self) -> None:
        app = self.make_app()
        sysext_root = app / "Contents/Library/SystemExtensions/com.example.sysext.systemextension"
        sysext_macos = sysext_root / "Contents/MacOS"
        sysext_macos.mkdir(parents=True)
        with (sysext_root / "Contents/Info.plist").open("wb") as fh:
            dump(
                {
                    "CFBundleIdentifier": "com.example.sysext",
                    "CFBundleExecutable": "ExampleSysExt",
                },
                fh,
            )
        executable = sysext_macos / "ExampleSysExt"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(executable.stat().st_mode | 0o111)

        proc = self.run_script(str(app), "--pass-id", "PASS-102")

        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        data = json.loads(
            (self.project / "findings/analysis/PASS-102-example-target-map.json").read_text(
                encoding="utf-8"
            )
        )
        kinds = [component["kind"] for component in data["components"]]
        self.assertIn("system-extension", kinds)
        self.assertIn("system-extension", data["classification"]["surfaces"])
        self.assertIn("os-component", data["classification"]["surfaces"])
        self.assertIn("apple-os-components", data["classification"]["family_labels"])
        # No double-counting: the system extension's MacOS executable is not also recorded as `executable`.
        self.assertFalse(
            any(
                component["path"]
                == "Contents/Library/SystemExtensions/com.example.sysext.systemextension/Contents/MacOS/ExampleSysExt"
                and component["kind"] == "executable"
                for component in data["components"]
            )
        )

    def test_endpoint_security_named_extension_marks_es_client_surface(self) -> None:
        app = self.make_app()
        sysext_root = app / "Contents/Library/SystemExtensions/com.example.endpointsecurity.systemextension"
        sysext_macos = sysext_root / "Contents/MacOS"
        sysext_macos.mkdir(parents=True)
        with (sysext_root / "Contents/Info.plist").open("wb") as fh:
            dump({"CFBundleIdentifier": "com.example.endpointsecurity"}, fh)

        proc = self.run_script(str(app), "--pass-id", "PASS-103")

        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        data = json.loads(
            (self.project / "findings/analysis/PASS-103-example-target-map.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIn("endpoint-security-client", data["classification"]["surfaces"])

    def test_launchd_plist_with_machservices_records_structured_data(self) -> None:
        app = self.make_app()
        launchd_dir = app / "Contents/Library/LaunchDaemons"
        launchd_dir.mkdir(parents=True)
        with (launchd_dir / "com.example.daemon.plist").open("wb") as fh:
            dump(
                {
                    "Label": "com.example.daemon",
                    "ProgramArguments": ["/Library/Application Support/Example/daemon"],
                    "MachServices": {
                        "com.example.daemon.service": True,
                        "com.example.daemon.privileged": True,
                    },
                    "RunAtLoad": True,
                },
                fh,
            )

        proc = self.run_script(str(app), "--pass-id", "PASS-104")

        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        data = json.loads(
            (self.project / "findings/analysis/PASS-104-example-target-map.json").read_text(
                encoding="utf-8"
            )
        )
        launchd_components = [
            component for component in data["components"] if component["kind"] == "launchd-plist"
        ]
        self.assertTrue(launchd_components)
        services = launchd_components[0].get("launchd", {}).get("mach_services", [])
        self.assertIn("com.example.daemon.service", services)
        self.assertIn("com.example.daemon.privileged", services)
        self.assertIn("launchd-machservices", data["classification"]["surfaces"])
        self.assertIn(
            "com.example.daemon.privileged",
            data["os_component"]["mach_services"],
        )

    def test_framework_target_kind_marks_os_component_surface(self) -> None:
        framework = self.tmp / "Example.framework"
        versions_a = framework / "Versions/A"
        versions_a.mkdir(parents=True)
        (versions_a / "Example").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        (framework / "Example").symlink_to("Versions/A/Example")
        (framework / "Versions/Current").symlink_to("A")

        proc = self.run_script(str(framework), "--pass-id", "PASS-105")

        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        data = json.loads(
            (self.project / "findings/analysis/PASS-105-example-framework-target-map.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(data["target"]["kind"], "framework")
        self.assertIn("os-component", data["classification"]["surfaces"])
        self.assertIn("apple-os-components", data["classification"]["family_labels"])

    def test_watch_decision_support_records_per_surface_maturity(self) -> None:
        app = self.make_app()
        sysext_root = app / "Contents/Library/SystemExtensions/com.example.sysext.systemextension"
        sysext_macos = sysext_root / "Contents/MacOS"
        sysext_macos.mkdir(parents=True)
        with (sysext_root / "Contents/Info.plist").open("wb") as fh:
            dump({"CFBundleIdentifier": "com.example.sysext"}, fh)

        proc = self.run_script(str(app), "--pass-id", "PASS-110")

        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        data = json.loads(
            (self.project / "findings/analysis/PASS-110-example-target-map.json").read_text(
                encoding="utf-8"
            )
        )
        maturity = data["decision_support"]["maturity"]
        self.assertEqual(maturity.get("xpc-services"), "full-recipe")
        self.assertEqual(maturity.get("system-extension"), "basic-inventory")
        # The os-component umbrella should also appear since system-extension is present.
        self.assertEqual(maturity.get("os-component"), "full-recipe")
        gaps = data["decision_support"]["coverage_gaps"]
        self.assertTrue(
            any("system-extension" in gap and "Basic-inventory" in gap for gap in gaps),
            msg=f"expected basic-inventory gap mentioning system-extension; gaps={gaps}",
        )

        corpus = (self.project / "CORPUS.md").read_text(encoding="utf-8")
        # Watch row carries a maturity summary segment ("full-recipe: ...; basic-inventory: ...").
        self.assertIn("basic-inventory: system-extension", corpus)
        # Re-running intake updates the row in place rather than appending duplicates.
        second = self.run_script(str(app), "--pass-id", "PASS-110")
        self.assertEqual(second.returncode, 0, msg=second.stdout + second.stderr)
        corpus = (self.project / "CORPUS.md").read_text(encoding="utf-8")
        self.assertEqual(
            corpus.count("| example | PASS-110 | `findings/analysis/PASS-110-example-dossier.json` |"),
            1,
        )

    def test_unknown_surface_is_marked_manual_route_needed(self) -> None:
        # Pure-function spot check: an unrecognized surface name falls back to manual-route-needed.
        maturity = start_target_module.surface_maturity_map(["xpc-services", "frobnicator"])
        self.assertEqual(maturity["xpc-services"], "full-recipe")
        self.assertEqual(maturity["frobnicator"], "manual-route-needed")
        gaps = start_target_module.maturity_coverage_gaps(maturity)
        self.assertTrue(any("frobnicator" in gap for gap in gaps))

    def test_os_topology_row_populated_for_os_component_target(self) -> None:
        binary = self.tmp / "examplesd"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(binary.stat().st_mode | 0o111)

        proc = self.run_script(str(binary), "--pass-id", "PASS-200")

        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        corpus = (self.project / "CORPUS.md").read_text(encoding="utf-8")
        # The OS Component Topology row leads with the target id.
        topology_section = corpus.split("## OS Component Topology", 1)[1].split("##", 1)[0]
        self.assertIn("| examplesd | daemon |", topology_section)

        # Ordinary (non-OS-component) targets do not pollute the OS Topology table.
        plain = self.tmp / "tool"
        plain.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        plain.chmod(plain.stat().st_mode | 0o111)
        proc2 = self.run_script(str(plain), "--pass-id", "PASS-201")
        self.assertEqual(proc2.returncode, 0, msg=proc2.stdout + proc2.stderr)
        corpus = (self.project / "CORPUS.md").read_text(encoding="utf-8")
        topology_section = corpus.split("## OS Component Topology", 1)[1].split("##", 1)[0]
        self.assertNotIn("| tool |", topology_section)

        # Re-intake updates the existing row in place; no duplicate.
        proc3 = self.run_script(str(binary), "--pass-id", "PASS-200")
        self.assertEqual(proc3.returncode, 0, msg=proc3.stdout + proc3.stderr)
        corpus = (self.project / "CORPUS.md").read_text(encoding="utf-8")
        topology_section = corpus.split("## OS Component Topology", 1)[1].split("##", 1)[0]
        self.assertEqual(topology_section.count("| examplesd | daemon |"), 1)

    def test_apple_source_map_row_only_when_apple_source_metadata_provided(self) -> None:
        app = self.tmp / "AppleishApp.app"
        contents = app / "Contents"
        macos = contents / "MacOS"
        macos.mkdir(parents=True)
        with (contents / "Info.plist").open("wb") as fh:
            dump(
                {
                    "CFBundleIdentifier": "com.apple.example",
                    "CFBundleExecutable": "AppleishApp",
                },
                fh,
            )
        executable = macos / "AppleishApp"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(executable.stat().st_mode | 0o111)

        source_root = self.tmp / "apple-source-cache/dyld-1042.1"
        source_root.mkdir(parents=True)

        proc = self.run_script(
            str(app),
            "--pass-id",
            "PASS-202",
            "--source-root",
            str(source_root),
            "--source-ref",
            "1042.1",
            "--source-url",
            "https://opensource.apple.com/source/dyld/dyld-1042.1.tar.gz",
        )

        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        corpus = (self.project / "CORPUS.md").read_text(encoding="utf-8")
        apple_section = corpus.split("## Apple Source Map", 1)[1].split("##", 1)[0]
        self.assertIn("| appleishapp |", apple_section)
        self.assertIn("dyld", apple_section)
        self.assertIn("1042.1", apple_section)

        # A non-Apple target with source metadata does NOT populate the Apple Source Map table.
        binary = self.tmp / "thirdparty-tool"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(binary.stat().st_mode | 0o111)
        proc2 = self.run_script(
            str(binary),
            "--pass-id",
            "PASS-203",
            "--source-root",
            str(source_root),
            "--source-ref",
            "v1.0",
            "--source-url",
            "https://example.invalid/repo",
        )
        self.assertEqual(proc2.returncode, 0, msg=proc2.stdout + proc2.stderr)
        corpus = (self.project / "CORPUS.md").read_text(encoding="utf-8")
        apple_section = corpus.split("## Apple Source Map", 1)[1].split("##", 1)[0]
        self.assertNotIn("thirdparty-tool", apple_section)


class TestStartTargetHelpers(unittest.TestCase):
    """Pure-function tests for U1 helpers (parsing logic, no subprocess required)."""

    def test_parse_dyld_dependencies_extracts_private_framework_and_cache(self) -> None:
        sample = """
/usr/bin/example:
\t/System/Library/PrivateFrameworks/Quagmire.framework/Quagmire (compatibility version 1.0.0, current version 1.0.0)
\t/System/Library/Frameworks/Foundation.framework/Foundation (compatibility version 300.0.0, current version 1900.0.0)
\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1311.0.0)
""".strip("\n")
        result = start_target_module.parse_dyld_dependencies(sample)

        self.assertTrue(any("Quagmire" in dep for dep in result["all_deps"]))
        self.assertTrue(any("PrivateFrameworks" in dep for dep in result["private_framework_deps"]))
        self.assertTrue(result["dyld_cache_origin"])
        self.assertTrue(any("/System/Library/" in path for path in result["dyld_cache_paths"]))

    def test_parse_dyld_dependencies_handles_empty_input(self) -> None:
        result = start_target_module.parse_dyld_dependencies("")

        self.assertEqual(result["all_deps"], [])
        self.assertEqual(result["private_framework_deps"], [])
        self.assertFalse(result["dyld_cache_origin"])

    def test_apply_codesign_evidence_marks_apple_signed_for_software_signing(self) -> None:
        sample = "Authority=Software Signing\nTeamIdentifier=APPLE_TEAM\nIdentifier=com.apple.example\n"
        info = start_target_module.apply_codesign_evidence(
            {"apple_signed": False, "authority": "", "team_id": "", "evidence": ""},
            sample,
        )

        self.assertTrue(info["apple_signed"])
        self.assertEqual(info["authority"], "Software Signing")
        self.assertEqual(info["team_id"], "APPLE_TEAM")
        self.assertIn("Software Signing", info["evidence"])

    def test_apply_codesign_evidence_does_not_mark_third_party_authority(self) -> None:
        sample = "Authority=Developer ID Application: Acme\nTeamIdentifier=ACME123\n"
        info = start_target_module.apply_codesign_evidence(
            {"apple_signed": False, "authority": "", "team_id": "", "evidence": ""},
            sample,
        )

        self.assertFalse(info["apple_signed"])
        self.assertEqual(info["team_id"], "ACME123")


if __name__ == "__main__":
    unittest.main()
