# Flatseal Zero-Day Analysis — Findings

Status: IN PROGRESS (started 2026-07-24)

## Threat model

Flatseal is a GJS/GTK4 app that manages Flatpak permission *overrides*. Its own manifest
(`com.github.tchx84.Flatseal.json`) grants it:

- `--filesystem=/var/lib/flatpak/app:ro` and `--filesystem=xdg-data/flatpak/app:ro`
  → reads the `metadata`, `appdata.xml`/`metainfo.xml`, and `.desktop` files of **every installed app**
  (including a malicious/attacker-authored one).
- `--filesystem=xdg-data/flatpak/overrides:create`
  → **writes** `~/.local/share/flatpak/overrides/<app-id>` and `.../overrides/global`, which control the
  runtime sandbox permissions of **every** installed Flatpak app.
- `--talk-name=org.freedesktop.impl.portal.PermissionStore` → can change portal permissions.

**Primary attacker:** a malicious/untrusted Flatpak app the victim has installed. Its bundle files
(`metadata`, appstream XML, desktop entry) are untrusted input parsed by Flatseal.

**Impact tiers we are hunting:**
1. Crash Flatseal (DoS) via malformed input.
2. Make Flatseal write a *dangerous* override for another app (or global) → sandbox escape / privilege
   escalation for that app (e.g. `filesystems=host`, `LD_PRELOAD=…`, un-share network, own a bus name).
3. Arbitrary file read/write / path traversal in Flatseal's own (broader) sandbox.
4. Code execution (via a dependency parser bug, or by chaining the above).

## Approach registry (families)

- **F1 KeyFile write-injection** — can attacker metadata values be persisted into a user override file
  in a way that injects extra groups/keys (newline/`;`/`[section]` injection through GLib.KeyFile
  `set_value`/`get_value` raw semantics)? Targets: `shared.js:saveToKeyFile`,
  `variables.js:saveToKeyFile`, `unsupported.js:saveToKeyFile`, `permissions.js:_saveOverrides`.
- **F2 Parsing crash / DoS / ReDoS** — malformed metadata/override/appdata causing unhandled
  exceptions, infinite loops, or catastrophic regex backtracking. Targets: `variables.js` deserialize
  split `(?=;[^;]+=)`, `filesystemsOther.js` split logic, `permissions.js:_loadPermissionsForPath`.
- **F3 Path traversal / arbitrary FS** — crafted appId / launchable / installation Path used unsanitized
  in `GLib.build_filenamev`. Targets: `applications.js` (`_getBundlePathForAppId`,
  `getMetadataPathForAppId`, `getDesktopForAppData` using `appdata.launchable`,
  `_parseCustomInstallation`), `pathRow.js`, `relativePathRow.js`.
- **F4 Dependency bugs** — libappstream XML parse (appdata/metainfo/desktop), GLib.KeyFile, WebKit
  docs viewer, D-Bus portals `PermissionStore`. Clone + audit the specific calls.

## Confirmed findings

(none yet — investigation in progress)

## Ruled out / blocked

(none yet)
