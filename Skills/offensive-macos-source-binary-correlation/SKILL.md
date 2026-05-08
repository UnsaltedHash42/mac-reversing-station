---
name: offensive-macos-source-binary-correlation
description: >-
  Use for open-source or in-house macOS targets where source is available but
  the shipped binary remains the evidence source of truth.
folder: offensive-macos-source-binary-correlation
source: skillz-wave4
trigger_phrases:
  - "source binary correlation"
  - "source available"
  - "open source target"
  - "in-house source"
  - "source divergence"
  - "compare source to binary"
---

# Source-Binary Correlation

> **Channel boundary:** `REPO_MODE=analysis`. Source review guides binary
> confirmation; source review alone is not proof of shipped behavior.

## When To Use

Choose this skill when you have access to source and need to confirm what
actually shipped. The workflow changes depending on source quality:

**Open-source application** (VS Code, Firefox, Signal). Full build system
available; you can diff release tags against shipped binaries. High
confidence once you match the build commit.

**Apple component with partial source** (Security.framework, xnu,
libdispatch). Apple publishes subset source through apple-oss-distributions.
Internal-only headers, build flags, and private additions mean the source
is a guide, not ground truth. Expect divergence.

**In-house code** (your employer's macOS agent, internal tool). You have
the repo and CI. The question is whether the deployed binary matches a
known commit or has local patches, stale dependencies, or unreleased fixes.

**Vendor with leaked or decompiled reference** (rare). Treat as low
confidence; leaked source may be stale, partial, or deliberately poisoned.
Verify every claim against the binary independently.

## Lab Topology

```
Workstation                          Lab Host
──────────────────────────────────── ────────────────────────────────────
source checkout (git)                shipped binary in ~/Targets/
  - grep, read, diff                 Ghidra headless (decompile, symbols)
  - identify claims                  macre-vm-mcp (codesign, strings, nm)
  - write correlation table          LLDB (dynamic confirmation)
```

Source stays on the workstation. The binary stays on the lab host. You
correlate across the SSH boundary using function names, strings, symbol
tables, and decompiled output fetched via MCP.

## Workflow

1. Record source metadata in `CORPUS.md`: repo URL, commit/tag, clone path.
2. Identify source claims worth confirming. Prioritize: security checks,
   authorization logic, IPC validation, sandbox policy, entitlement
   references, and conditional compilation guards.
3. For each claim, find binary evidence:
   - **Symbol match:** `nm` or Ghidra function list contains the function.
   - **String match:** string literals from the source appear in the binary.
   - **Decompilation match:** Ghidra decompilation of the function matches
     source logic structurally.
   - **Build metadata:** embedded version strings, `__DATA,__objc_imageinfo`,
     or Info.plist values match the source commit.
4. Mark confidence per claim: `aligned`, `partial`, `divergent`, or `unverified`.
5. Route dynamic confirmation through Gatehouse only when a static binary
   anchor exists and confidence is `partial` or `divergent`.

## What Source Can Tell You

- Function names and call graph structure.
- Intended authorization flow and trust model.
- Expected IPC message schemas and reply shapes.
- Conditional compilation branches (`#if DEBUG`, `#if INTERNAL_BUILD`).
- Dependencies and framework linkage.

## What Source Cannot Tell You About The Shipped Binary

**Internal-only build flags.** Apple components and enterprise apps
commonly use `#if INTERNAL_BUILD`, `#if !RELEASE`, `#if TARGET_OS_SIMULATOR`.
Code inside these guards exists in source but is stripped at compile time
in the release build. If your claim depends on code inside a conditional,
verify the function exists in the binary before proceeding.

**ABI drift and private headers.** Apple ships headers that differ from
what they build against internally. A function signature in public source
may take different arguments in the actual framework. Watch for extra
parameters, reordered struct fields, or renamed selectors.

**Dead code stripped at link.** The linker's `-dead_strip` pass removes
unreachable functions. Source may contain helper functions that never
appear in the shipped binary because nothing references them.

**Inlined-then-changed functions.** Small functions get inlined by the
compiler. If the source later changes that function, the inlined copies
in older callers retain the old behavior. Decompilation of the caller
shows the pre-change logic even though source shows the fix.

**Conditionalized code.** Some source has runtime feature flags
(`os_feature_enabled`, `NSUserDefaults` checks, server-side toggles).
The code is compiled in but may be unreachable at runtime depending on
configuration state.

## Worked Example: tccd and Security.framework

**Source:** apple-oss-distributions/Security (latest public tag).
**Binary:** `/usr/libexec/tccd` from macOS 14.x.

### Step 1: identify a claim

In the public Security source, `TCCAccessCheck` calls
`SecTaskCopyValueForEntitlement` to verify the caller holds a specific
TCC entitlement before granting access. The source shows:

```c
CFTypeRef value = SecTaskCopyValueForEntitlement(task, entitlement, NULL);
if (value == NULL) { deny(); return; }
```

Claim: `tccd` checks entitlements via `SecTaskCopyValueForEntitlement`
before allowing TCC access.

### Step 2: find binary evidence

Via Ghidra MCP, search the `tccd` function list:
- `SecTaskCopyValueForEntitlement` appears as an imported symbol. Confirmed.
- Decompile callers: the logic matches the source pattern.

Via `nm -u /usr/libexec/tccd`:
- `_SecTaskCopyValueForEntitlement` is in the undefined symbols (imported
  from Security.framework). Confirmed.

Confidence: **aligned** for this specific function.

### Step 3: find a divergence

The public source references `kTCCAccessCheckDeny` as an early-return
constant. In the shipped binary, the string literal is absent (it's an
enum, not a string). However, the function `_TCCAccessPreflight` in the
binary has a branch structure not present in the public source: an
additional check against a plist cache path that doesn't appear in any
public header.

Confidence for that function: **divergent**. The binary has logic the
source doesn't show.

### Step 4: record and route

```markdown
## Source-Binary Correlation — tccd

- Target ID: PASS-001
- Source ref: apple-oss-distributions/Security @ tag securityd-1234
- Binary artifact: /usr/libexec/tccd (macOS 14.4, sha256: abcdef...)
- Claims:
  | Function | Source says | Binary shows | Confidence |
  |----------|-----------|--------------|------------|
  | TCCAccessCheck | entitlement gate | entitlement gate | aligned |
  | TCCAccessPreflight | simple deny path | extra plist-cache branch | divergent |
- Next: decompile the divergent branch and triage as candidate.
```

## Failure Modes

**Source claims a function exists, binary doesn't have it.**
Likely stripped by dead-code elimination, behind a build flag, or renamed.
Mark `unverified`. Check if a similar function with a different name
exists (compiler may have merged or renamed).

**Binary has functions not in source.**
Private additions, auto-generated code (protocol buffers, bridging),
or functions from statically-linked dependencies. Not necessarily
interesting unless they touch security boundaries.

**Source shows a fix, binary still has the old code.**
The deployed binary may predate the source commit you're reading.
Check the binary's build version (`otool -l | grep -A4 LC_BUILD_VERSION`)
against the source tag date.

**String appears in source but not in binary.**
Strings used only in debug/assert paths are often stripped in release
builds. Or the string was a format argument that got constant-folded
away.

## Hunt: source-divergence bugs

A distinct bug class exists where the shipped binary behaves differently
from what source review would predict. This matters because:

- Security audits performed against source alone miss these bugs.
- Developers believe the fix is deployed when the binary still ships
  the old code.
- Conditional compilation creates implicit trust boundaries that aren't
  documented.

When you find a `divergent` correlation, ask:
1. Does the divergent code path cross a trust boundary?
2. Is the divergent behavior weaker than what source implies?
3. Could an attacker reach the divergent path?

If all three are yes, you have a candidate. Create it with class
`source-divergence` and include the source ref, binary evidence, and
the specific behavioral difference.

## Output Shape

```markdown
## Source-Binary Correlation

- Target ID:
- Source ref:
- Binary artifact:
- Claims:
  | Function | Source says | Binary shows | Confidence |
  |----------|-----------|--------------|------------|
  | ... | ... | ... | aligned/partial/divergent/unverified |
- Next confirmation step:
```

## See Also

- `docs/playbooks/investigation-recipes.md` — `correlate-source-binary` recipe
- `Skills/offensive-macos-watch-static-analysis/SKILL.md`
- `Skills/offensive-macos-gatehouse-ghidra-lldb/SKILL.md`
- `Skills/offensive-macos-hunt-wrong-door/SKILL.md`
