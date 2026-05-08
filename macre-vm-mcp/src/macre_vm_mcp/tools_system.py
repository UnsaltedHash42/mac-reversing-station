"""System-facing tools: ``log stream``, ``launchctl``, and OS metadata."""

from __future__ import annotations

import re
from typing import Any

from fastmcp import FastMCP

from ._proc import run

LAUNCHD_DOMAIN_RE = re.compile(r"^(system|user/[0-9]+|gui/[0-9]+)$")
UNSAFE_PATH_RE = re.compile(r"[\n\r;&|`$<>]")


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
    services: set[str] = set()
    in_machservices = False
    brace_depth = 0
    service_re = re.compile(r"([A-Za-z0-9_-]+\.){2,}[A-Za-z0-9_.-]+")
    for line in stdout.splitlines():
        if "MachServices" in line or "mach services" in line.lower():
            in_machservices = True
            brace_depth = max(brace_depth, line.count("{") - line.count("}"))
        elif in_machservices:
            brace_depth += line.count("{") - line.count("}")
        if in_machservices:
            for match in service_re.finditer(line):
                services.add(match.group(0))
            if brace_depth <= 0 and "}" in line:
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
    deps = []
    for line in stdout.splitlines()[1:]:
        stripped = line.strip()
        if not stripped:
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


def first_nonzero(*codes: int) -> int:
    for code in codes:
        if code != 0:
            return code
    return 0
