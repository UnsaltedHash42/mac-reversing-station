---
name: offensive-macos-maproom-recipes
description: >-
  Use when selecting or maintaining investigation recipes that map goals to
  skills, scripts, MCP tools, outputs, and project-state updates.
folder: offensive-macos-maproom-recipes
source: skillz-wave4
trigger_phrases:
  - "maproom"
  - "recipe registry"
  - "which recipe"
  - "investigation recipe"
---

# Maproom Recipes

> **Channel boundary:** `REPO_MODE=analysis`. Recipes route evidence collection;
> they are not exploit chains or proof by themselves.

## When To Use

- Watch recommends a recipe ID.
- The operator asks what ordered workflow should run for a goal.
- A new reusable static/dynamic workflow needs to be added without bloating the README.

## Workflow

1. Read `docs/playbooks/investigation-recipes.md`.
2. Match the operator goal to one recipe ID.
3. List the required input state, tools, expected outputs, and files to update.
4. If no recipe fits, use `inventory-first-manual-routing` and record the gap.
5. Keep recipes compact and validate references with `scripts/validate-recipes.py`.

## See Also

- `docs/playbooks/investigation-recipes.md`
- `scripts/validate-recipes.py`
- `Skills/offensive-macos-watch-static-analysis/SKILL.md`
