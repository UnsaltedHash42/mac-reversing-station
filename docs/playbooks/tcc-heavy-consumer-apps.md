# TCC-Heavy Consumer Apps

Use this playbook for apps that request or broker privacy-sensitive permissions: Accessibility, Screen Recording, Automation, camera, microphone, Desktop/Documents, Downloads, contacts, calendars, photos, or Full Disk Access.

## Common Artifacts

- TCC service strings and privacy entitlements.
- Accessibility and Automation APIs.
- Apple Events usage and target app identifiers.
- File picker, bookmark, drag-and-drop, or recent-document access.
- Helpers or XPC services that inherit or proxy privacy access.
- Cached grants, persistent access lists, and app group containers.

## Primary Ontology Classes

- `VULN-TCC-ATTRIBUTION`
- `VULN-SANDBOX-ESCAPE-PRIMITIVE`
- `VULN-SCOPED-BOOKMARKS`
- `VULN-KEYCHAIN-TRUST`
- `VULN-FILE-AUTHORITY-TRANSFER`
- `VULN-XPC-CLIENT-VALIDATION`
- `VULN-IPC-CONFUSED-DEPUTY`

## First-Pass Checks

- Use synthetic data and dedicated test users.
- Inventory privacy entitlements and TCC prompt paths.
- Map who appears in prompts, who receives grants, and which resource is accessed.
- Inspect whether helpers or XPC services proxy privacy access to lower-privilege clients.
- Check persistent authorization stores such as bookmarks, keychain items, and container plists.

## False-Positive Traps

- Prompting for privacy access is expected.
- User-approved file access is expected.
- The bug is attribution mismatch, grant transfer, unauthorized persistence, or access outside the intended subject/resource/lifetime.
- Do not treat UI confusion as a vulnerability without proving grant or access mismatch.

## Minimum Evidence For Escalation

- Prompt or grant subject, target resource, and actual recipient.
- Synthetic protected data before/after access.
- TCC or persistent authorization state when safe to inspect.
- Dedicated test user, snapshot, and cleanup notes.
- Root-cause path showing where identity or authorization binding failed.
