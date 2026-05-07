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
---

# Source-Binary Correlation

> **Channel boundary:** `REPO_MODE=analysis`. Source review guides binary
> confirmation; source review alone is not proof of shipped behavior.

## When To Use

- The target has a source checkout, release URL, commit/tag, symbols, or SAST report.
- A source finding needs to be mapped to a shipped `.app`, framework, helper, or binary.
- Source and binary may diverge and confidence needs to be explicit.

## Workflow

1. Record source metadata in `CORPUS.md` and the dossier.
2. Identify source claims worth confirming in the shipped artifact.
3. Map each claim to binary evidence: symbols, strings, functions, build metadata, or decompiled code.
4. Mark confidence as aligned, partial, divergent, or unverified.
5. Route dynamic confirmation through Bridge only after a static binary anchor exists.

## Output Shape

```markdown
## Source-Binary Correlation

- Target ID:
- Source ref:
- Binary artifact:
- Correlation confidence:
- Source claim:
- Binary anchor:
- Next confirmation step:
```

## See Also

- `docs/playbooks/investigation-recipes.md`
- `Skills/offensive-macos-scryer-static-analysis/SKILL.md`
- `Skills/offensive-macos-bridge-ghidra-lldb/SKILL.md`
