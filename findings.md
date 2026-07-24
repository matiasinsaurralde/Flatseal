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

### C1 — DoS: malicious AppStream release timestamp crashes Flatseal on startup (CONFIRMED)

**File:** `src/models/applications.js:352-356` (`getAppDataForAppId`)

```js
if (release.get_timestamp() !== null) {
    const ts = release.get_timestamp();
    const date = new Date(ts * 1000);
    appdata.date = date.toISOString().substring(0, 10);   // <-- throws RangeError
}
```

`release.get_timestamp()` returns the attacker-controlled Unix timestamp (seconds) from an installed
app's `…/files/share/metainfo/<appid>.metainfo.xml` (or `appdata.xml`) `<release timestamp="…"/>`.
JS `Date` is only valid within ±8.64e15 ms, so any timestamp ≥ **8 640 000 000 001 s** makes
`ts*1000` exceed the range and `new Date(...).toISOString()` throws `RangeError: Invalid time value`.
Verified empirically in node (see scratchpad/date_crash.js): ts=8640000000000 OK, ts=8640000000001 THROWS.

**Reachability / impact:** the throwing block is NOT wrapped in try/catch (only `metadata.parse_file`
is). `getAppDataForAppId` is called from `getAll()` (`applications.js:376`) inside a `.map`, which is
called from `window.js:147 _setupApplications()` (also no try/catch) during window construction, and
from `appInfoViewer._setup()`. A single malicious app therefore makes `getAll()` throw → the app list
never builds → **Flatseal fails to open / crashes**, and stays broken until the malicious app is
uninstalled (persistent DoS). One malicious app also poisons enumeration of ALL apps.

Minimal payload (metainfo.xml): `<releases><release version="1.0" timestamp="9999999999999999"/></releases>`.

## Ruled out (so far)

- **pathRow.js regexes (`_pathRE`, `_optionRE`) ReDoS** — reconstructed exactly and fuzzed in node
  (scratchpad/redos_pathrow.js). The mandatory `/` (or option-prefix) delimiter per `+`/`*` iteration
  makes the partition unique → linear time even at length 100+. NOT catastrophic. BLOCKED unless a new
  mechanism appears.
- **variables.js regexes** (`VAR_REGEXP`, deserialize split `(?=;[^;]+=)`, `split(/[=](.*)/s)`) — linear
  in node up to 100k+ chars. No ReDoS.
- **portals.js / info.js** — D-Bus calls wrapped in safe* try/catch; `.flatpak-info` is runtime-provided
  (trusted). No obvious injection into D-Bus method args beyond appId (a bus-validated app name).

## Ruled out / blocked

(none yet)
