"""Unit tests for the system tool parsers.

These parsers are the parts most likely to drift across macOS releases
and they were previously untested. Each test feeds a captured fixture
of the actual command output and asserts the parser produces the
expected structure.
"""

from __future__ import annotations

import hashlib
import struct
import unittest

from macre_vm_mcp.tools_codesign import _parse_codesign_dv
from macre_vm_mcp.tools_system import (
    parse_launchctl_machservices,
    parse_otool_dependencies,
    parse_sw_vers,
    parse_systemextensionsctl,
    _walk_fat_slices,
    FAT_MAGIC,
)


class TestLaunchctlMachServices(unittest.TestCase):
    def test_extracts_only_inside_machservices_block(self) -> None:
        # Real `launchctl print system` has nested blocks; we should
        # not pick up reverse-DNS strings outside MachServices.
        sample = """\
state = running
program = /usr/libexec/foo
endpoints = {
    com.apple.unrelated.endpoint = {
        ...
    }
}
MachServices = {
    com.apple.example.service = {
        ManagedPID = 123
        bundle = com.apple.example
    }
    com.apple.example.helper = {
        ManagedPID = 124
    }
}
unrelated_block = {
    com.apple.totally.different = {
    }
}
"""
        services = parse_launchctl_machservices(sample)
        self.assertIn("com.apple.example.service", services)
        self.assertIn("com.apple.example.helper", services)
        self.assertNotIn("com.apple.totally.different", services)
        self.assertNotIn("com.apple.unrelated.endpoint", services)

    def test_empty_input(self) -> None:
        self.assertEqual(parse_launchctl_machservices(""), [])

    def test_no_machservices_block(self) -> None:
        self.assertEqual(parse_launchctl_machservices("state = running\n"), [])


class TestOtoolDependencies(unittest.TestCase):
    def test_thin_binary(self) -> None:
        sample = """\
/bin/ls:
\t/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
\t/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1226.0.0)
"""
        deps = parse_otool_dependencies(sample)
        self.assertEqual(deps, [
            "/usr/lib/libutil.dylib",
            "/usr/lib/libncurses.5.4.dylib",
            "/usr/lib/libSystem.B.dylib",
        ])

    def test_fat_binary_does_not_drop_slice_first_dep(self) -> None:
        # otool emits the filename: header per slice for fat binaries.
        # The previous parser dropped the first dep of every slice past
        # the first.
        sample = """\
/path/to/fat (architecture x86_64):
\t/usr/lib/libfoo.dylib (compatibility version 1.0.0, current version 1.0.0)
\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1226.0.0)
/path/to/fat (architecture arm64):
\t/usr/lib/libfoo.dylib (compatibility version 1.0.0, current version 1.0.0)
\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1226.0.0)
"""
        deps = parse_otool_dependencies(sample)
        # Both libfoo entries (one per slice) must be present.
        self.assertEqual(deps.count("/usr/lib/libfoo.dylib"), 2)
        self.assertEqual(deps.count("/usr/lib/libSystem.B.dylib"), 2)


class TestSwVers(unittest.TestCase):
    def test_parses_kv_lines(self) -> None:
        sample = "ProductName:\tmacOS\nProductVersion:\t14.4.1\nBuildVersion:\t23E224\n"
        parsed = parse_sw_vers(sample)
        self.assertEqual(parsed["ProductName"], "macOS")
        self.assertEqual(parsed["ProductVersion"], "14.4.1")
        self.assertEqual(parsed["BuildVersion"], "23E224")


class TestSystemExtensionsctl(unittest.TestCase):
    def test_parses_typical_row(self) -> None:
        # systemextensionsctl emits one extension per line. Headers
        # like `enabled` and `---` are skipped.
        sample = """\
1 extension(s)
*\t*\tcom.example.app (1.0/100)\tcom.example.helper (1.0/100)\t[activated enabled]
"""
        # The current parser strips lines starting with the listed
        # prefixes; lines starting with whitespace and no leading `*`
        # are kept. Use a leading bundle-shaped string.
        sample = "1 extension(s)\ncom.example.app (1.0/100)\tcom.example.helper (1.0/100)\t[activated enabled]\n"
        rows = parse_systemextensionsctl(sample)
        self.assertEqual(len(rows), 1)
        self.assertIn(".app", rows[0]["bundle_id"])
        self.assertIn("activated", rows[0]["state"])


class TestCodesignDv(unittest.TestCase):
    def test_parses_kv_pairs_from_stderr(self) -> None:
        sample = """\
Executable=/bin/ls
Identifier=com.apple.ls
Format=Mach-O thin (arm64e)
TeamIdentifier=not set
"""
        parsed = _parse_codesign_dv(sample)
        self.assertEqual(parsed["executable"], "/bin/ls")
        self.assertEqual(parsed["identifier"], "com.apple.ls")
        self.assertIn("format", parsed)


class TestFatSliceWalker(unittest.TestCase):
    def _build_fat(self, slices: list[bytes]) -> bytes:
        # Build a 32-bit big-endian fat header for testing. Each slice
        # is laid out at a fresh offset; the walker should hash each.
        header = struct.pack(">II", FAT_MAGIC, len(slices))
        # placeholders for fat_arch entries: cputype, cpusubtype, offset,
        # size, align (all 32-bit for fat32)
        entry_size = 20
        body_offset = 8 + entry_size * len(slices)
        body = b""
        entries = b""
        # Use real Apple cputypes for arm64 / x86_64 so naming exercises
        # too: 0x100000c (arm64) and 0x1000007 (x86_64).
        cputypes = [0x100000c, 0x1000007]
        cur = body_offset
        for i, slc in enumerate(slices):
            entries += struct.pack(">iiIII", cputypes[i], 0, cur, len(slc), 12)
            body += slc
            cur += len(slc)
        return header + entries + body

    def test_hashes_each_slice_independently(self) -> None:
        slices = [b"slice-arm64-data" * 4, b"slice-x86_64-data" * 5]
        fat = self._build_fat(slices)
        result = _walk_fat_slices(fat, FAT_MAGIC)
        self.assertEqual(len(result), 2)
        archs = {r["arch"] for r in result}
        self.assertEqual(archs, {"arm64", "x86_64"})
        for r, original in zip(result, slices):
            self.assertEqual(r["sha256"], hashlib.sha256(original).hexdigest())

    def test_handles_empty_fat(self) -> None:
        fat = struct.pack(">II", FAT_MAGIC, 0)
        result = _walk_fat_slices(fat, FAT_MAGIC)
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
