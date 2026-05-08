"""System-facing tools: ``log stream``, ``launchctl``, and OS metadata."""

from __future__ import annotations

import hashlib
import plistlib
import re
import struct
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from ._proc import run
from .tools_codesign import _parse_codesign_dv

LAUNCHD_DOMAIN_RE = re.compile(r"^(system|user/[0-9]+|gui/[0-9]+)$")
UNSAFE_PATH_RE = re.compile(r"[\n\r;&|`$<>]")

# Mach-O magic numbers for slice extraction in hash_target.
MH_MAGIC_64 = 0xfeedfacf
MH_CIGAM_64 = 0xcffaedfe
MH_MAGIC = 0xfeedface
MH_CIGAM = 0xcefaedfe
FAT_MAGIC = 0xcafebabe
FAT_CIGAM = 0xbebafeca
FAT_MAGIC_64 = 0xcafebabf
FAT_CIGAM_64 = 0xbfbafeca

# Apple's CPU type / subtype subset we care about for slice naming.
_CPU_NAMES = {
    0x1000007: "x86_64",
    0x100000c: "arm64",
    0x0000007: "i386",
    0x000000c: "arm",
    0x100000d: "arm64_32",
}


def register(mcp: FastMCP) -> None:
    @mcp.tool
    def log_stream(
        predicate: str,
        style: str = "compact",
        timeout_sec: float = 10.0,
    ) -> dict[str, Any]:
        """Run ``log stream --predicate <expr>`` for a bounded duration.

        Example predicate:
            eventMessage CONTAINS "TCC"
            subsystem == "com.apple.tccd" AND eventMessage CONTAINS "prompt"

        ``style`` is one of default | compact | json | ndjson | syslog.
        """
        return run(
            ["/usr/bin/log", "stream", "--predicate", predicate, "--style", style],
            timeout=timeout_sec,
        ).to_dict()

    @mcp.tool
    def launchctl_list(service_filter: str | None = None) -> dict[str, Any]:
        """Run ``launchctl list``. Optionally pass a substring filter.

        The filter is applied to stdout *after* capture (client-side grep),
        because ``launchctl list`` does not accept a regex.
        """
        result = run(["/bin/launchctl", "list"])
        stdout = result.stdout
        if service_filter:
            stdout = "\n".join(
                line for line in stdout.splitlines() if service_filter in line
            )
        return {
            "returncode": result.returncode,
            "stdout": stdout,
            "stderr": result.stderr,
            "timed_out": result.timed_out,
            "filter_applied": service_filter,
        }

    @mcp.tool
    def launchctl_print(service_target: str) -> dict[str, Any]:
        """Run ``launchctl print <service-target>``.

        ``service-target`` is a domain/service spec — e.g.
        ``system/com.apple.tccd``, ``gui/$(id -u)/com.apple.Finder``.
        """
        return run(["/bin/launchctl", "print", service_target]).to_dict()

    @mcp.tool
    def launchd_machservices(domain: str = "system") -> dict[str, Any]:
        """Return launchd MachService facts for a launchd domain.

        ``domain`` must be ``system``, ``user/<uid>``, or ``gui/<uid>``. The
        tool runs the read-only command ``launchctl print <domain>``, extracts
        likely MachService names, and preserves raw stdout for operator review.
        """
        if not valid_launchd_domain(domain):
            return {
                "returncode": 2,
                "stdout": "",
                "stderr": "invalid domain; expected system, user/<uid>, or gui/<uid>",
                "timed_out": False,
                "domain": domain,
                "mach_services": [],
            }
        result = run(["/bin/launchctl", "print", domain], timeout=20.0)
        return {
            **result.to_dict(),
            "domain": domain,
            "mach_services": parse_launchctl_machservices(result.stdout),
        }

    @mcp.tool
    def system_extension_list() -> dict[str, Any]:
        """Run ``systemextensionsctl list`` and return parsed extension rows.

        The command is read-only. Parsed rows are best-effort because Apple has
        changed the output format across macOS releases; raw stdout is returned
        alongside the structured rows.
        """
        result = run(["/usr/bin/systemextensionsctl", "list"], timeout=20.0)
        return {
            **result.to_dict(),
            "extensions": parse_systemextensionsctl(result.stdout),
        }

    @mcp.tool
    def framework_dependency_map(binary_path: str, max_depth: int = 1) -> dict[str, Any]:
        """Map ``otool -L`` dependencies for a binary or framework executable.

        ``binary_path`` is passed as a single argv element (no shell). Obvious
        shell metacharacters and newlines are rejected. ``max_depth`` is capped
        to keep recursive dependency maps bounded.
        """
        if unsafe_path(binary_path):
            return {
                "returncode": 2,
                "stdout": "",
                "stderr": "unsafe binary_path",
                "timed_out": False,
                "binary_path": binary_path,
                "dependencies": [],
            }

        depth = max(0, min(int(max_depth), 2))
        seen: set[str] = set()
        queue: list[tuple[str, int]] = [(binary_path, 0)]
        dependencies: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []

        while queue:
            path, current_depth = queue.pop(0)
            if path in seen:
                continue
            seen.add(path)
            result = run(["/usr/bin/otool", "-L", path], timeout=20.0)
            if result.returncode != 0:
                errors.append({"path": path, "stderr": result.stderr})
                continue
            for dep in parse_otool_dependencies(result.stdout):
                dep_row = {
                    "from": path,
                    "path": dep,
                    "private_framework": "/System/Library/PrivateFrameworks/" in dep,
                    "system_framework": dep.startswith("/System/Library/Frameworks/"),
                    "dyld_shared_cache_candidate": dep.startswith(("/System/Library/", "/usr/lib/")),
                }
                dependencies.append(dep_row)
                if current_depth < depth and dep.startswith("/") and not unsafe_path(dep):
                    queue.append((dep, current_depth + 1))

        return {
            "returncode": 0 if not errors else 1,
            "stdout": "",
            "stderr": "",
            "timed_out": False,
            "binary_path": binary_path,
            "max_depth": depth,
            "dependencies": dependencies,
            "errors": errors,
        }

    @mcp.tool
    def procinfo(target: str) -> dict[str, Any]:
        """One-shot identity dump for a running PID or a binary path.

        Combines codesign metadata, entitlements, bundle id, launchd
        plist (if any matches the path), and -- for a PID -- the
        responsible parent / executable path. The agent reaches for
        this whenever it needs to answer "what is this process and
        what is it allowed to do" without composing four tools.

        ``target`` is either an integer PID or a filesystem path.
        """
        result: dict[str, Any] = {
            "target": target,
            "kind": "pid" if str(target).isdigit() else "path",
            "errors": [],
        }

        path = target
        pid = None

        if str(target).isdigit():
            pid = int(target)
            ps = run(["/bin/ps", "-o", "comm=,ppid=,uid=,user=", "-p", str(pid)],
                     timeout=10.0)
            result["ps"] = ps.to_dict()
            if ps.returncode == 0 and ps.stdout.strip():
                fields = ps.stdout.strip().split()
                if fields:
                    path = fields[0]
                    result["resolved_path"] = path
                    if len(fields) >= 4:
                        result["ppid"] = fields[1]
                        result["uid"] = fields[2]
                        result["user"] = fields[3]
            else:
                result["errors"].append("ps returned no row")

        if not path or not isinstance(path, str):
            result["errors"].append("could not resolve path from target")
            return result

        codesign = run(
            ["/usr/bin/codesign", "-dvvv", "--entitlements", "-",
             "--requirements", "-", path],
            timeout=15.0,
        )
        result["codesign"] = codesign.to_dict()
        result["codesign_parsed"] = _parse_codesign_dv(codesign.stderr)

        ent = run(["/usr/bin/codesign", "-d", "--entitlements", ":-", path],
                  timeout=15.0)
        if ent.stdout:
            try:
                result["entitlements"] = plistlib.loads(
                    ent.stdout.encode("utf-8", errors="surrogateescape"))
            except Exception as exc:
                result["entitlements_parse_error"] = str(exc)

        # Match path to any launchd plist that names it.
        import pathlib
        search_dirs = [
            "/Library/LaunchDaemons", "/Library/LaunchAgents",
            "/System/Library/LaunchDaemons", "/System/Library/LaunchAgents",
        ]
        user_agents = str(pathlib.Path.home() / "Library/LaunchAgents")
        if pathlib.Path(user_agents).is_dir():
            search_dirs.append(user_agents)
        launchd_match = run(
            ["/usr/bin/grep", "-l", "-r", "-F", path] + search_dirs,
            timeout=20.0,
        )
        if launchd_match.stdout.strip():
            result["launchd_plists"] = launchd_match.stdout.strip().splitlines()

        return result

    @mcp.tool
    def hash_target(path: str, slice_arch: str | None = None) -> dict[str, Any]:
        """SHA256 the binary at ``path``, per-slice for fat universals.

        Returns the file-level sha256 and, for fat binaries, a per-slice
        hash table keyed by arch name (arm64, x86_64, etc.) so dynamic
        evidence can pin to the exact byte sequence that ran.

        If ``slice_arch`` is provided, returns only that slice's hash.
        """
        if unsafe_path(path):
            return {
                "returncode": 2, "stdout": "", "stderr": "unsafe path",
                "timed_out": False, "path": path, "errors": ["unsafe path"],
            }
        try:
            data = Path(path).read_bytes()
        except OSError as exc:
            return {
                "returncode": 1, "stdout": "", "stderr": str(exc),
                "timed_out": False, "path": path, "errors": [str(exc)],
            }

        full = hashlib.sha256(data).hexdigest()
        result: dict[str, Any] = {
            "returncode": 0, "stdout": "", "stderr": "", "timed_out": False,
            "path": path, "size": len(data), "sha256": full,
            "kind": "thin",
        }

        if len(data) < 8:
            return result

        magic = struct.unpack(">I", data[:4])[0]
        if magic in (FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64):
            result["kind"] = "fat"
            try:
                slices = _walk_fat_slices(data, magic)
            except Exception as exc:
                result["errors"] = [f"fat parse failed: {exc}"]
                return result
            result["slices"] = slices
            if slice_arch:
                for s in slices:
                    if s["arch"] == slice_arch:
                        result["sha256"] = s["sha256"]
                        result["size"] = s["size"]
                        break
                else:
                    result["errors"] = [f"slice {slice_arch!r} not found"]
        elif magic in (MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64):
            result["kind"] = "thin"

        return result

    @mcp.tool
    def os_build_snapshot() -> dict[str, Any]:
        """Capture read-only OS build, SIP, and software snapshot facts.

        Returns ``sw_vers``, ``system_profiler SPSoftwareDataType``, and
        ``csrutil status`` results so OS-component evidence can pin the lab VM
        state that produced an observation.
        """
        sw_vers = run(["/usr/bin/sw_vers"], timeout=10.0)
        profiler = run(
            ["/usr/sbin/system_profiler", "SPSoftwareDataType"],
            timeout=30.0,
        )
        csrutil = run(["/usr/bin/csrutil", "status"], timeout=10.0)
        return {
            "returncode": first_nonzero(sw_vers.returncode, profiler.returncode, csrutil.returncode),
            "stdout": "",
            "stderr": "\n".join(part for part in (sw_vers.stderr, profiler.stderr, csrutil.stderr) if part),
            "timed_out": sw_vers.timed_out or profiler.timed_out or csrutil.timed_out,
            "sw_vers": sw_vers.to_dict(),
            "software": profiler.to_dict(),
            "sip": csrutil.to_dict(),
            "parsed": parse_sw_vers(sw_vers.stdout),
        }


def valid_launchd_domain(value: str) -> bool:
    return bool(LAUNCHD_DOMAIN_RE.fullmatch(value.strip()))


def unsafe_path(value: str) -> bool:
    return not value or bool(UNSAFE_PATH_RE.search(value))


def parse_launchctl_machservices(stdout: str) -> list[str]:
    """Extract MachService names from a `launchctl print <domain>` dump.

    The output has nested key = { ... } blocks. The MachServices block we
    want is one of those. The previous implementation used max() on the
    running depth which only ever rose, so once we entered MachServices
    we never left -- subsequent unrelated reverse-DNS strings polluted
    the output. This pass tracks the running depth correctly and exits
    when the MachServices block's open brace closes.
    """
    services: set[str] = set()
    service_re = re.compile(r"([A-Za-z0-9_-]+\.){2,}[A-Za-z0-9_.-]+")
    in_machservices = False
    block_depth = 0  # depth at the moment MachServices opened
    cur_depth = 0

    for line in stdout.splitlines():
        opens = line.count("{")
        closes = line.count("}")
        if not in_machservices:
            if "MachServices" in line or "mach services" in line.lower():
                in_machservices = True
                # We may see "MachServices = {" on the same line, or the
                # opening brace on the next line. Either way, the depth
                # *after* the opens on this line is where we want to
                # return to before declaring the block done.
                cur_depth += opens - closes
                block_depth = cur_depth - (opens - closes)
                continue
            cur_depth += opens - closes
            continue

        # Inside the MachServices block.
        for match in service_re.finditer(line):
            services.add(match.group(0))
        cur_depth += opens - closes
        if cur_depth <= block_depth:
            in_machservices = False

    return sorted(services)


def parse_systemextensionsctl(stdout: str) -> list[dict[str, str]]:
    rows = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("---", "enabled", "*")):
            continue
        bundle_match = re.search(r"([A-Za-z0-9_-]+\.){2,}[A-Za-z0-9_.-]+", stripped)
        state_match = re.search(r"\[([^\]]+)\]", stripped)
        if bundle_match or state_match:
            rows.append(
                {
                    "bundle_id": bundle_match.group(0) if bundle_match else "",
                    "state": state_match.group(1) if state_match else "",
                    "raw": stripped,
                }
            )
    return rows


def parse_otool_dependencies(stdout: str) -> list[str]:
    """Parse ``otool -L`` stdout into a list of dependency paths.

    For fat binaries otool emits a "filename:" header per slice, so the
    naive `splitlines()[1:]` skip silently dropped the first dep of every
    slice past the first. We instead skip lines that look like headers
    (end with ":" and don't contain a leading whitespace = path indent).
    """
    deps: list[str] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # otool path lines are indented under the header; headers are
        # flush-left and end with `:`.
        if not line.startswith((" ", "\t")) and stripped.endswith(":"):
            continue
        deps.append(stripped.split(" (", 1)[0])
    return deps


def parse_sw_vers(stdout: str) -> dict[str, str]:
    parsed = {}
    for line in stdout.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def _walk_fat_slices(data: bytes, magic: int) -> list[dict[str, Any]]:
    """Walk a fat Mach-O wrapper and hash each contained slice.

    Supports 32- and 64-bit fat headers and both endiannesses. Each
    fat_arch entry carries (cputype, cpusubtype, offset, size, align).
    """
    big = magic in (FAT_MAGIC, FAT_MAGIC_64)
    is_64 = magic in (FAT_MAGIC_64, FAT_CIGAM_64)
    endian = ">" if big else "<"
    nfat = struct.unpack(endian + "I", data[4:8])[0]
    if nfat > 64:
        raise ValueError(f"implausible nfat_arch={nfat}")

    slices: list[dict[str, Any]] = []
    if is_64:
        entry_size = 32
        fmt = endian + "iiQQI"
    else:
        entry_size = 20
        fmt = endian + "iiIII"

    cur = 8
    for _ in range(nfat):
        if len(data) < cur + entry_size:
            break
        cputype, cpusubtype, offset, size, align = struct.unpack(
            fmt, data[cur:cur + entry_size]
        )
        cur += entry_size
        end = offset + size
        if offset < 0 or end > len(data):
            slices.append({
                "arch": _CPU_NAMES.get(cputype, f"cputype_{cputype}"),
                "cputype": cputype, "cpusubtype": cpusubtype,
                "offset": offset, "size": size,
                "sha256": None, "error": "out of bounds",
            })
            continue
        slice_bytes = data[offset:end]
        slices.append({
            "arch": _CPU_NAMES.get(cputype, f"cputype_{cputype}"),
            "cputype": cputype, "cpusubtype": cpusubtype,
            "offset": offset, "size": size,
            "sha256": hashlib.sha256(slice_bytes).hexdigest(),
        })
    return slices


def first_nonzero(*codes: int) -> int:
    for code in codes:
        if code != 0:
            return code
    return 0
