---
name: offensive-macos-electron-surface-pack
description: >-
  Use when a macOS target appears to be Electron-based and needs ASAR,
  package, preload, IPC, native module, fuse, sandbox, or update review.
folder: offensive-macos-electron-surface-pack
source: skillz-wave4
trigger_phrases:
  - "electron app"
  - "asar"
  - "preload script"
  - "electron ipc"
  - "extract asar"
---

# Electron Surface Pack

> **Channel boundary:** `REPO_MODE=analysis`. Electron settings and IPC shapes
> are triage signals until tied to packaged-artifact evidence and confirmed impact.

## When To Use

- Watch detects ASAR archives, Electron frameworks, `package.json`, preload scripts, or native `.node` modules.
- The operator needs Electron-specific static review before choosing dynamic checks.
- A target mixes browser, Node, native module, and macOS bundle surfaces.

## Workflow

1. Read the dossier and Electron indicators.
2. Extract `app.asar` with `scripts/extract-asar.sh` (see "Extracting the asar" below). Upstream `asar` / `@electron/asar` ENOENT-bail on the first missing unpacked file, leaving an empty extract dir; the wrapper substitutes empty buffers and emits a manifest.
3. Identify packaged entrypoints, preload scripts, IPC boundaries, native modules, and update channels.
4. Check security posture: context isolation, sandbox, Node integration, exposed bridge APIs, fuses, and ASAR integrity when evidence is available.
5. Map risky shapes to binary or packaged-artifact anchors before creating candidate rows.
6. Route LLDB or runtime work only after a specific static anchor exists.

## Extracting the asar

```bash
scripts/extract-asar.sh \
    <Bundle>/Contents/Resources/app.asar \
    <out-dir>
```

Reads `<asar>.unpacked/` siblings when the asar header marks a file
`unpacked: true`. If the unpacked file is missing, writes an empty buffer
in its place rather than aborting, and records the path in
`<out-dir>/.asar-extract-manifest.json` under `substitutedEmpty[]`.

Pure Node, no npm install. Tested on Node 20.15. PASS-001 baseline:
14174 files, 420 inlined + 13754 copied-from-unpacked on Rocket.Chat
4.13.0.

## Output Shape

```markdown
## Electron Surface Review

- Target ID:
- Packaged entrypoints:
- Preload / IPC surfaces:
- Native modules:
- Update channel:
- Triage signals:
- Binary or packaged-artifact anchors:
- Next recipe:
```

## See Also

- `docs/playbooks/investigation-recipes.md`
- `Skills/offensive-macos-watch-static-analysis/SKILL.md`
- `Skills/offensive-macos-vuln-ontology/SKILL.md`
