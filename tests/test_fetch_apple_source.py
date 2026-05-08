import importlib.util
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
import urllib.error
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts/fetch-apple-source.py"


def load_fetch_module():
    spec = importlib.util.spec_from_file_location("fetch_apple_source", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("fetch_apple_source", module)
    spec.loader.exec_module(module)
    return module


fetch_module = load_fetch_module()


def make_tarball_bytes(component: str, release: str) -> bytes:
    """Build an in-memory tarball with one harmless file under a single top dir."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        top_dir = f"{component}-{component}-{release}"
        info = tarfile.TarInfo(name=f"{top_dir}/README")
        payload = b"sample\n"
        info.size = len(payload)
        info.type = tarfile.REGTYPE
        tar.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


class StubResponse:
    def __init__(self, payload: bytes) -> None:
        self._buffer = io.BytesIO(payload)

    def read(self, size: int = -1) -> bytes:
        return self._buffer.read(size if size and size > 0 else -1)

    def close(self) -> None:
        self._buffer.close()


class TestFetchAppleSource(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.tmp = Path(self.tmpdir.name)
        self.cache = self.tmp / "sources/apple"

    def test_resolve_url_uses_github_apple_oss_distributions_by_default(self) -> None:
        url = fetch_module.resolve_url("dyld", "1042.1", "github")
        self.assertEqual(
            url,
            "https://github.com/apple-oss-distributions/dyld/archive/refs/tags/dyld-1042.1.tar.gz",
        )

    def test_resolve_url_supports_legacy_opensource_path(self) -> None:
        url = fetch_module.resolve_url("xnu", "8020", "opensource")
        self.assertEqual(
            url,
            "https://opensource.apple.com/source/xnu/xnu-8020.tar.gz",
        )

    def test_dry_run_resolves_url_without_writing(self) -> None:
        result = fetch_module.fetch_apple_source(
            component="dyld",
            release="1042.1",
            cache_dir=self.cache,
            dry_run=True,
        )
        self.assertEqual(result["status"], "dry-run")
        self.assertEqual(result["component_dir"], str((self.cache / "dyld/1042.1").resolve()))
        self.assertEqual(
            result["start_target_args"],
            {
                "--source-root": str((self.cache / "dyld/1042.1").resolve()),
                "--source-ref": "1042.1",
                "--source-url": result["url"],
            },
        )
        self.assertFalse(self.cache.exists())

    def test_fetch_writes_tarball_extracts_and_marks_cache(self) -> None:
        payload = make_tarball_bytes("dyld", "1042.1")
        opener_calls: list[tuple[str, int]] = []

        def stub_opener(url: str, timeout: int) -> StubResponse:
            opener_calls.append((url, timeout))
            return StubResponse(payload)

        result = fetch_module.fetch_apple_source(
            component="dyld",
            release="1042.1",
            cache_dir=self.cache,
            url_opener=stub_opener,
        )

        self.assertEqual(result["status"], "fetched-and-extracted")
        self.assertEqual(len(opener_calls), 1)
        self.assertTrue(opener_calls[0][0].startswith("https://github.com/apple-oss-distributions/"))
        component_dir = Path(result["component_dir"])
        self.assertTrue(component_dir.is_dir())
        self.assertTrue((component_dir / ".extracted").is_file())
        archive = Path(result["archive_path"])
        self.assertTrue(archive.is_file())
        self.assertGreater(archive.stat().st_size, 0)
        # Extracted content lands under the cache directory.
        extracted = list(component_dir.rglob("README"))
        self.assertTrue(extracted, msg="expected at least one README extracted")

    def test_rerun_with_existing_cache_is_a_no_op(self) -> None:
        payload = make_tarball_bytes("dyld", "1042.1")

        def stub_opener(url: str, timeout: int) -> StubResponse:
            return StubResponse(payload)

        first = fetch_module.fetch_apple_source(
            component="dyld",
            release="1042.1",
            cache_dir=self.cache,
            url_opener=stub_opener,
        )
        self.assertEqual(first["status"], "fetched-and-extracted")

        # Second run: the opener should NOT be called.
        opener_calls = []

        def fail_if_called(url: str, timeout: int) -> StubResponse:
            opener_calls.append(url)
            raise AssertionError("opener should not be invoked on cache-hit")

        second = fetch_module.fetch_apple_source(
            component="dyld",
            release="1042.1",
            cache_dir=self.cache,
            url_opener=fail_if_called,
        )
        self.assertEqual(second["status"], "cache-hit")
        self.assertEqual(opener_calls, [])

    def test_invalid_component_name_fails_cleanly(self) -> None:
        with self.assertRaises(fetch_module.FetchError) as ctx:
            fetch_module.fetch_apple_source(
                component="../etc/passwd",
                release="1042.1",
                cache_dir=self.cache,
                dry_run=True,
            )
        self.assertIn("invalid component", str(ctx.exception))

    def test_invalid_release_fails_cleanly(self) -> None:
        with self.assertRaises(fetch_module.FetchError):
            fetch_module.fetch_apple_source(
                component="dyld",
                release="rel ease",
                cache_dir=self.cache,
                dry_run=True,
            )

    def test_network_failure_is_reported_not_crash(self) -> None:
        def failing_opener(url: str, timeout: int):
            raise urllib.error.URLError("network down")

        with self.assertRaises(fetch_module.FetchError) as ctx:
            fetch_module.fetch_apple_source(
                component="dyld",
                release="1042.1",
                cache_dir=self.cache,
                url_opener=failing_opener,
            )
        self.assertIn("network error", str(ctx.exception))

    def test_http_error_is_reported_not_crash(self) -> None:
        def http_error_opener(url: str, timeout: int):
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, io.BytesIO(b""))

        with self.assertRaises(fetch_module.FetchError) as ctx:
            fetch_module.fetch_apple_source(
                component="missing-component",
                release="1.0",
                cache_dir=self.cache,
                url_opener=http_error_opener,
            )
        self.assertIn("HTTP 404", str(ctx.exception))

    def test_unsafe_tarball_member_is_rejected_during_extract(self) -> None:
        # Build a tarball with a path-traversal member.
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            info = tarfile.TarInfo(name="../escaped")
            payload = b"escape\n"
            info.size = len(payload)
            info.type = tarfile.REGTYPE
            tar.addfile(info, io.BytesIO(payload))
            safe_info = tarfile.TarInfo(name="component-1.0/README")
            safe_payload = b"safe\n"
            safe_info.size = len(safe_payload)
            safe_info.type = tarfile.REGTYPE
            tar.addfile(safe_info, io.BytesIO(safe_payload))
        unsafe_payload = buffer.getvalue()

        def stub_opener(url: str, timeout: int) -> StubResponse:
            return StubResponse(unsafe_payload)

        result = fetch_module.fetch_apple_source(
            component="component",
            release="1.0",
            cache_dir=self.cache,
            url_opener=stub_opener,
        )
        component_dir = Path(result["component_dir"])
        # Safe member extracted; unsafe traversal member dropped.
        self.assertTrue((component_dir / "component-1.0/README").is_file())
        self.assertFalse((self.tmp / "escaped").exists())


class TestFetchAppleSourceCli(unittest.TestCase):
    def test_cli_dry_run_outputs_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "cache"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "dyld",
                    "--release",
                    "1042.1",
                    "--cache-dir",
                    str(cache),
                    "--dry-run",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["component"], "dyld")
            self.assertEqual(payload["release"], "1042.1")
            self.assertEqual(payload["status"], "dry-run")
            self.assertIn("--source-root", payload["start_target_args"])

    def test_cli_invalid_component_returns_nonzero_exit(self) -> None:
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "../etc/passwd",
                "--release",
                "1.0",
                "--dry-run",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("invalid component", proc.stderr)


if __name__ == "__main__":
    unittest.main()
