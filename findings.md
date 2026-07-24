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

### C2 — DoS: unguarded `load_from_file` on malformed `metadata` crashes when app is opened (CONFIRMED)

**File:** `src/models/applications.js:246-247` (`getMetadataForAppId`)

```js
const keyFile = new GLib.KeyFile();
keyFile.load_from_file(path, 0);   // <-- NOT wrapped; only the following get_value is
try { data.runtime = keyFile.get_value(group, 'runtime'); } catch (err) { ... }
```

A malicious app's `metadata` file with invalid GLib KeyFile syntax (e.g. a bare line `garbage`) makes
`load_from_file` throw `G_KEY_FILE_ERROR_PARSE`. `permissions.js:163` wraps the identical call in
try/catch precisely because it throws; this one doesn't. Reached from `appInfoViewer._setup`
(`appInfoViewer.js:76`) via `window.js:308` inside the `row-activated` signal handler → crashes when the
user selects the malicious app (does not break the whole list like C1). Same root class as C1.
`_parseCustomInstallation` (`applications.js:124`) has the same unguarded call but its files live in
system config, not attacker-controlled.

### C3 — `launchable` path traversal → arbitrary file read parsed as desktop entry (CONFIRMED, sandbox-bounded)

**File:** `src/models/applications.js:263-268` (`getDesktopForAppData`)

`appdata.launchable` (from the malicious app's own AppStream `<launchable type="desktop-id">`,
`applications.js:338-340`, no `/` or `..` validation) is concatenated:
`build_filenamev([bundlePath,'export','share','applications', launchable])` then `parse_file(…, DESKTOP_ENTRY)`.
Verified against system glib: `g_build_filenamev` does NOT normalize `..` and does NOT reset on an
absolute later component (it re-anchors under base). So `launchable = ../../../../../../etc/passwd`
resolves to `/etc/passwd` and is opened + parsed; the surfaced datum is the stock icon name (low-bandwidth
read/exfil). Runs automatically for every app via `getAll()`→`window.js:147`. In the SHIPPED sandbox the
read is bounded to already-mounted trees (`…/flatpak/app` ro, `…/overrides`), so limited extra reach;
becomes true arbitrary-read if Flatseal runs with broader perms/unsandboxed. Genuine unsanitized
path-build bug. Fix: require `GLib.path_get_basename(launchable) === launchable`.

## Plausible / preconditioned

### P1 — env-var override-write relocation (`FLATPAK_USER_DIR` / `HOST_XDG_DATA_HOME`)

`applications.js:88-104 _getUserPath()` returns `GLib.getenv('FLATPAK_USER_DIR')` (or, in-flatpak,
`HOST_XDG_DATA_HOME`) unvalidated; it becomes the base for `permissions.js:142 _getBaseOverridesPath` →
`mkdir_with_parents`, `save_to_file`, `unlink`. An attacker who controls Flatseal's *launch environment*
can redirect override writes to an arbitrary dir (e.g. drop `[Context] filesystems=host;` into another
installation's overrides). Confirmed behavior; requires env control (not a malicious *installed app*),
so a weaker attacker model. Same for `FLATPAK_SYSTEM_DIR`, `FLATPAK_CONFIG_DIR`, `FLATPAK_INFO_PATH`,
`FLATSEAL_PORTAL_BUS_NAME`.

### P2 — app directory literally named `global` spoofs the global-override sentinel

`globalModel.js:21 isGlobalOverride(appId)` is a bare `appId === 'global'` compare. A malicious app whose
install directory is named `global` is enumerated as a normal app yet treated everywhere as the global
overrides entry (`permissions.js`, `window.js:299/353`); `_getOverridesPath` → `…/overrides/global`.
Logic/UI-confusion, not a path escape. Low severity on its own.

### F-ENV — confined `[Environment]` value-splitting / env laundering (CONFIRMED, low-impact)

**Files:** `src/models/variables.js:26` (`VAR_REGEXP = /^[^;\s]+=[\S ]+$/` — forbids `;` in the key but
`[\S ]+` ALLOWS `;` in the value) and `variables.js:76-80` (`deserialize` splits on `/(?=;[^;]+=)/`).

A malicious app metadata `[Environment]` entry `FOO=a;PATH=/evil` is a single Flatpak env var
`FOO` = `a;PATH=/evil`. Flatseal loads it as one original, but `deserialize` tears it into two rows
`FOO=a` and `PATH=/evil`. After ANY user interaction (which triggers `_updateModels`/`_saveOverrides`),
`updateFromProxyProperty` writes BOTH `FOO=a` and a NEW standalone `PATH=/evil` as overrides
(verified in node by the widgets agent). Net effect: Flatseal "activates" a separate `PATH` (or any
`NAME=value`) override that raw Flatpak parsing of the manifest would NOT have set — an env-var
laundering / confused-deputy: a value hidden inside another var's value (evading manifest review)
becomes a real distinct env override on the same app. Impact is bounded — it stays within the
`[Environment]` group of the SAME app (cannot cross into `filesystems=`/bus policy), and the app author
already controls its own env — so this is data-integrity, not privilege-crossing. Fix: tighten
VAR_REGEXP to forbid `;` in values, or don't split values.

## Ruled out (so far)

- **pathRow.js regexes (`_pathRE`, `_optionRE`) ReDoS** — reconstructed exactly and fuzzed in node
  (scratchpad/redos_pathrow.js). The mandatory `/` (or option-prefix) delimiter per `+`/`*` iteration
  makes the partition unique → linear time even at length 100+. NOT catastrophic. BLOCKED unless a new
  mechanism appears.
- **variables.js regexes** (`VAR_REGEXP`, deserialize split `(?=;[^;]+=)`, `split(/[=](.*)/s)`) — linear
  in node up to 100k+ chars. No ReDoS.
- **portals.js / info.js** — D-Bus calls wrapped in safe* try/catch; `.flatpak-info` is runtime-provided
  (trusted). No obvious injection into D-Bus method args beyond appId (a bus-validated app name).
- **KeyFile write-injection (F1 family) — REFUTED (real-GLib tested).** `get_value` values are always
  single-line (a newline terminates the line at parse), so no attacker metadata value can carry a raw
  `0x0A` to inject a new `[group]`/`key=` on re-serialize, even though `set_value`/`to_data` write
  verbatim/unescaped. `unsupported` catch-all is gated `overrides && !global` (only the user's own
  override file, never metadata). Saves write ONLY `_overrides` (never `_originals`/`_globals`), and
  key names with `[`/`]` make `load_from_file` throw (caught → `emit('failed')`). Latent hardening note:
  if any override read ever switches `get_value`→`get_string`, injection becomes live.
- **Pango markup injection — REFUTED.** No `set_markup`/`use-markup` anywhere in `src/**`. The one
  attacker string hitting a markup-honoring title (`appName`→`Adw.ActionRow.set_title`) is escaped with
  `GLib.markup_escape_text` (`applicationRow.js:32`). All other attacker strings go to plain
  `GtkLabel.set_label`/`set_text`. `set_subtitle(appId)` is unescaped but appId is a bus-name-form
  basename (defense-in-depth only).
- **Cross-key / cross-group override injection — REFUTED** (independently, via node round-trips): tokens
  are split on load and re-joined symmetrically; `set_value` cannot synthesize a `[Group]` header; bus
  names only ever become keys under their own `[… Bus Policy]` group.
- **appId path traversal — REFUTED.** appId = `GLib.path_get_basename` of a dir entry → always a single
  path component; cannot introduce `../`. Absolute-component injection into `build_filenamev` is
  re-anchored under the base (verified against system glib), so only `../` escapes — and appId can't
  carry it. (Only `launchable`, a freer AppStream string, can — see C3.)

## Ruled out / blocked

(none yet)
