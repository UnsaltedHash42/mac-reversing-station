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
---

# Electron Surface Pack

> **Channel boundary:** `REPO_MODE=analysis`. Electron settings and IPC shapes
> are triage signals until tied to packaged-artifact evidence and confirmed impact.

## When To Use

- Scryer detects ASAR archives, Electron frameworks, `package.json`, preload scripts, or native `.node` modules.
- The operator needs Electron-specific static review before choosing dynamic checks.
- A target mixes browser, Node, native module, and macOS bundle surfaces.

## Workflow

1. Read the dossier and Electron indicators.
2. Identify packaged entrypoints, preload scripts, IPC boundaries, native modules, and update channels.
3. Check security posture: context isolation, sandbox, Node integration, exposed bridge APIs, fuses, and ASAR integrity when evidence is available.
4. Map risky shapes to binary or packaged-artifact anchors before creating candidate rows.
5. Route LLDB or runtime work only after a specific static anchor exists.

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
- `Skills/offensive-macos-scryer-static-analysis/SKILL.md`
- `Skills/offensive-macos-vuln-ontology/SKILL.md`
