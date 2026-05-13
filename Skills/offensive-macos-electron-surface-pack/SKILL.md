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

Steps 2, 4, 5, and 6 are mandatory before the surface review can be marked
complete. PASS-001 ran 4 + 5 + 6 ad-hoc and missed every signal each was
designed to catch; the Output Shape below requires evidence from each.

1. Read the dossier and Electron indicators.
2. Extract `app.asar` with `scripts/extract-asar.sh` (see "Extracting the asar" below). Upstream `asar` / `@electron/asar` ENOENT-bail on the first missing unpacked file, leaving an empty extract dir; the wrapper substitutes empty buffers and emits a manifest.
3. Identify packaged entrypoints, preload scripts, IPC boundaries, native modules, and update channels.
4. **Read Electron fuses** with `npx @electron/fuses read --app <Bundle>.app`. Record the value of every fuse — `RunAsNode`, `EnableNodeCliInspectArguments`, `EnableEmbeddedAsarIntegrityValidation`, `OnlyLoadAppFromAsar`, `LoadBrowserProcessSpecificV8Snapshot`, `GrantFileProtocolExtraPrivileges`. Any one wrong fuse converts a renderer bug into full RCE or "any read primitive → code loading"; missing this step at intake erases the lift the rest of the surface review provides. ~5 sec; mandatory regardless of urgency.
5. **Audit `contextBridge.exposeInMainWorld` calls** in every preload script. For each `exposeInMainWorld(<name>, <object>)` call, record (a) the bridge name, (b) the property names exposed, (c) whether arguments are type-checked before reaching the main process, and (d) whether `contextIsolation: true` is set on the owning `BrowserWindow`. A bridge function that hands the renderer the ability to spawn shell commands — even framed as a "dev helper" — is renderer-to-shell RCE. Step 5 cannot be deferred to "task #N" — at minimum, surface review must include one grep result per `exposeInMainWorld` call.
6. **Enumerate native modules.** `find <extract-dir>/app.asar.unpacked -name '*.node'` records every native (Mach-O) module shipped inside `app.asar.unpacked`. A `.node` runs in the renderer or browser process with full Node privilege and bypasses codesign-validation of the main `.app` at dlopen time — past Electron CVEs have rooted here. Each `.node` becomes its own scan target (`T-00N`) in `CORPUS.md`'s worklist; no native module ships without an entry.
7. Check remaining security posture: context isolation (already covered by step 5), sandbox, Node integration, exposed bridge APIs, and ASAR integrity when evidence is available.
8. Map risky shapes to binary or packaged-artifact anchors before creating candidate rows.
9. Route LLDB or runtime work only after a specific static anchor exists.

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
- Electron fuses (one line per fuse, value + source):
- contextBridge calls (one row per exposeInMainWorld, name + properties + isolation):
- Preload / IPC surfaces:
- Native modules (one line per *.node under app.asar.unpacked, with T-00N scan-target id):
- Update channel:
- Triage signals:
- Binary or packaged-artifact anchors:
- Next recipe:
```

A surface review with empty `Electron fuses`, `contextBridge calls`, or
`Native modules` rows is incomplete — those are the three places PASS-001
missed signal. Use `n/a` only when the target genuinely lacks the surface
(e.g., a preload-less Electron build), not when the operator skipped the
step.

## See Also

- `docs/playbooks/investigation-recipes.md`
- `Skills/offensive-macos-watch-static-analysis/SKILL.md`
- `Skills/offensive-macos-vuln-ontology/SKILL.md`
