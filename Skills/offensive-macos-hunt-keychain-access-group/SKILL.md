---
name: offensive-macos-hunt-keychain-access-group
description: >-
  Use when auditing apps and helpers for keychain confused-deputy bugs:
  shared access groups, kSecAttrAccessGroup queries, application-groups
  entitlements, ACLs that don't pin to the calling app's identity, keychain
  items written by app A that app B in the same access group can read.
  Fires on "keychain access group", "kSecAttrAccessGroup", "shared keychain
  acl", "keychain confused deputy".
folder: offensive-macos-hunt-keychain-access-group
source: skillz-wave7
trigger_phrases:
  - "keychain access group"
  - "kSecAttrAccessGroup"
  - "shared keychain acl"
  - "keychain confused deputy"
---

# Hunt: keychain access-group confused deputy

> Channel boundary: `REPO_MODE=analysis`.

## When to use

The target reads or writes the keychain via `SecItemAdd` / `SecItemCopyMatching` / `SecItemUpdate` (modern API) or `SecKeychainAddGenericPassword` / `SecKeychainFindGenericPassword` (legacy API). The target's entitlements declare `keychain-access-groups` or `com.apple.application-identifier` matching another app's. The target accepts identity-bearing input (server URL, session token, sync state) from another process via XPC, defaults, or a shared container, and stores it in the keychain.

## Lab topology

| Step | Surface | How |
|---|---|---|
| Static script sweep | lab host | `ghidra-mcp` + `~/ghidra-scripts/scan_persistent_authorization.py` |
| Entitlement read | lab host | `macre-vm-mcp entitlement_dump` (look for `keychain-access-groups`) |
| Bundle co-residency check | workstation | `codesign -d --entitlements - <other-bundles>` to find peers in the same group |
| ACL inspection | lab host | `security dump-keychain -a` on a fresh user account; manual ACL read in Keychain Access |
| Reachability harness | crash-test | minimal app signed with the same access group, attempting `SecItemCopyMatching` |
| Evidence | findings repo | TSV + entitlement dump + ACL transcript under `artifacts/`, hash-pinned |

## What the bug class is

iOS-style keychain access groups exist on macOS via the hardened runtime + entitlement plist. Two apps signed with `keychain-access-groups = (group1, group2)` and the same Team ID can read each other's keychain items in those groups. The original design is for an app suite to share credentials across components.

The bug class is when the *trust* assumed by an item's writer doesn't match the *visibility* the access group provides. Three shapes:

Sharing across trust boundaries. App A (privileged installer) writes a credential into a shared access group. App B (sandboxed feature) reads it. The credential bypasses sandbox or TCC because it's no longer mediated by user consent.

ACL omission. `SecItemAdd` without an ACL dictionary defaults to "all apps with this access group can read." If the writer expects ACL-gated access ("only my own bundle ID"), the default semantics surprise.

Group expansion across versions. App A ships in 2023 with no access groups; App A 2024 adds an access group. Items written by 2023 versions get inherited into the new group's visibility. (Apple-specific behavior depends on `kSecAttrSynchronizable` and the migration path.)

The invariant: every keychain item is written with an ACL that pins access to the requesting bundle's signing identity, and every keychain *read* validates that the returned item has the expected ACL — not just the expected service / account.

## Anchor pattern

Strong: tier-A `secitemadd_callsite` containing references to a CFDictionary that includes `kSecAttrAccessGroup`. The dict-arg recovery doesn't currently pull the group name out of the dictionary, but the callsite + `kSecAttrAccessGroup` string co-occurrence is enough to navigate.

Strong: tier-A `seckeychainadd_callsite` with a recovered `service=` arg that names a credential type (auth token, session ID, refresh token, sync state). The legacy API takes the service as a plain C string, which we recover.

Strong: in the entitlement dump (from `dump_xpc_listeners.py` `interesting_entitlement` rows), the presence of `keychain-access-groups` with more than one entry. That's design-by-intent sharing; verify what's actually shared.

Medium: tier-A `secitemcopymatching_callsite` whose containing function does not also call `SecItemCopyMatching`-with-an-ACL-predicate or check `kSecAttrAccessControl`. If the read trusts the result based only on `kSecAttrService` matching, an attacker who can write to the same group with the same service can substitute their value.

Weak: tier-C `keychain_string` rows alone. Common in any Apple-derived binary.

## Harness

Read the entitlements first:

```bash
codesign -d --entitlements - /Applications/<App>.app/Contents/MacOS/<binary>
```

Note `keychain-access-groups`. For each entry, find every other binary on the system that claims the same group. That's the trust boundary.

Run the scan to enumerate `secitemadd_callsite` and `secitemcopymatching_callsite` rows. For each, decompile and answer:

- What's in the dictionary at the callsite? Look for `kSecAttrService`, `kSecAttrAccount`, `kSecAttrAccessGroup`, `kSecAttrAccessControl`, `kSecMatchLimit`.
- Is there an `kSecAttrAccessControl` ACL? If yes, what's its constraint (`kSecAccessControlPrivateKeyUsage`, `kSecAccessControlBiometryCurrentSet`, etc.)?
- For reads: does the code branch on the read item's metadata, or just trust it?
- For writes: does the code set an ACL that pins to the calling identity?

Build a (writer, reader, item, ACL) inventory. The bugs live in items where a writer's ACL is weaker than the reader's trust assumption.

## Reachability

Sign a minimal probe app with the same `keychain-access-groups`:

```xml
<!-- Entitlements.plist -->
<plist version="1.0">
<dict>
    <key>keychain-access-groups</key>
    <array>
        <string>$(AppIdentifierPrefix)com.example.targetgroup</string>
    </array>
</dict>
</plist>
```

```bash
codesign --force --sign - --entitlements Entitlements.plist /tmp/probe.app
```

From the probe, query for the candidate item:

```c
NSDictionary *q = @{
    (id)kSecClass: (id)kSecClassGenericPassword,
    (id)kSecAttrService: @"<known-service-name>",
    (id)kSecMatchLimit: (id)kSecMatchLimitOne,
    (id)kSecReturnAttributes: @YES,
    (id)kSecReturnData: @YES,
};
CFTypeRef result = NULL;
OSStatus status = SecItemCopyMatching((CFDictionaryRef)q, &result);
```

If the probe gets the item without prompting, the access group is exposing it across the trust boundary you care about. The bug's impact is what's *in* that item.

Snapshot the lab VM. The probe is benign but the keychain state matters across tests.

## Triage

For each (writer, reader, item) triple, decide:

- Is the access group actually shared with apps under different user trust? (Sandboxed app + privileged helper is the classic case.)
- Does the writer's ACL pin reads to its own identity, or does it accept any peer in the group?
- Is the item's value sensitive enough that cross-app read is a real bug? (Auth tokens: yes. Cached UI state: probably not.)

Promote to `escalated` only when there's a real cross-trust read of a sensitive item. Confirm with the probe app.

## Pitfalls

Team ID is required for shared access groups. Apps signed with different Team IDs cannot share groups regardless of the entitlement. An attacker shipping a notarized app can't squat another Team's group.

Ad-hoc-signed code can claim any access group entitlement, but the keychain enforces the group at runtime by checking the requesting code's signing identity. SIP and the keychain daemon together prevent ad-hoc-signed code from reading another Team's items in practice.

iCloud-synchronized items (`kSecAttrSynchronizable`) have different visibility semantics than local items. An item that looks safe locally may sync up and be visible across user-attached devices.

The legacy API (`SecKeychain*`) is layered over `SecItem*` on modern macOS but uses different default ACLs. Code that mixes the two often has implicit ACL mismatches.

`security` CLI is your best friend for static keychain inspection. `security find-generic-password -g -s <service>` will print the value if your current process is allowed.

## Public anchors

Wojciech Reguła's "macOS keychain abuse" series (SecuRing). Patrick Wardle's posts on keychain item visibility. Multiple vendor disclosures around 2018–2022 where an updater app shared a keychain access group with the main app and stored a server URL the main app trusted.

## See also

- `Skills/offensive-macos-family-privileged-helpers/SKILL.md`
- `Skills/offensive-macos-hunt-private-framework-hijack/SKILL.md`
- `Skills/offensive-macos-tooling-cli-static/SKILL.md`
- `Skills/offensive-macos-poc-authoring/SKILL.md`
- `ghidra-scripts/scan_persistent_authorization.py`
- `ghidra-scripts/dump_xpc_listeners.py`
