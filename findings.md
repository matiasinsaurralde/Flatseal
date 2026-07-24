# Flatseal Zero-Day Analysis — Findings

Status: IN PROGRESS (started 2026-07-24)

## TL;DR — the surviving chain

**Primary (E1): a privilege-escalation "override permissions" bug in the filesystem permission-diff
engine.** A malicious Flatpak app can get Flatseal to silently rewrite a user's *negated* filesystem
override (e.g. the user's `!/` revocation) into a *positive grant* (`filesystems=/` — full host
read-write, a sandbox escape), triggered by any later unrelated user edit. Root cause:
`filesystemsOther.js:134` unconditionally `negate()`s "removed" originals with no `isNegated`/`_overrides`
guard. Independently reproduced in node. See ★ E1 below.

**Supporting DoS chains:** C1 (AppStream `<release timestamp>` overflow → uncaught `RangeError` →
Flatseal fails to open — persistent windowless startup DoS from one installed app) and C4 (unbounded
launchable/appdata file read → memory-exhaustion DoS at startup). C3 is a bounded path-traversal read.

Note on "crash the process": on the GNOME 50 / GJS runtime, uncaught JS exceptions are logged-and-
continued (NOT SIGABRT). So C1/C2 are functional DoS (windowless / degraded), not hard crashes. No
attacker-reachable hard `abort()` was found in the JS or in libappstream/libxml2/GKeyFile (XXE,
entity-bomb, desktop-parse all refuted against the real libraries).

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

### ★ E1 — PRIVILEGE ESCALATION: `filesystemsOther` diff logic flips a negation into a positive filesystem GRANT (CONFIRMED — independently reproduced)

**This is the primary finding — a real "overriding permissions" sandbox escape.**

**File:** `src/models/filesystemsOther.js:128-146` (`updateFromProxyProperty`), root cause the
`removedOriginals` computation at lines 128-134 — the **unconditional** `.map(p => negate(p))` (line 134)
with **no `isNegated` guard and no filter against `this._overrides`** (contrast `removedGlobals`
at 136-143 which guards `!isOverriden(this._originals, p)`).

**Mechanism.** For any path routed to `filesystemsOther` (anything except bare `host`/`host-os`/
`host-etc`/`home`):
1. When the app metadata AND the user's own `overrides/<app>` file BOTH contain the same *negated* path
   `!X`, `updateProxyProperty` (157-192) HIDES both from the displayed value (the original is filtered by
   `!isOverriden(this._overrides, p)`; the override by the `isOverriden(this._originals, p) && isNegated`
   filter) → the UI shows an EMPTY "Other files" list.
2. On the next save (triggered by ANY unrelated user toggle → `permissions.js:294 _updateModels` →
   re-derives every model), `updateFromProxyProperty` receives the empty displayed value, so the metadata
   original `!X` is not in `paths`. `removedOriginals` therefore treats it as "user-removed" and applies
   `negate(removeMode('!X'))` = **`X`** (a positive grant, because `negate` is symmetric), writing it to
   `_overrides`.
3. `_saveOverrides` persists `filesystems=X`. Flatpak merges the per-app override AFTER metadata, so `X`
   (read-write) wins → **the app gains the access the user had revoked.**

**Independently reproduced** (scratchpad/verify_escalation.js — a faithful port of the exact source):
```
metadata !/  + user override !/   -> UI shows ""  -> saved override = "/"     *** ESCALATION ***
metadata !~/.ssh + user ovr !~/.ssh-> UI shows ""  -> saved override = "~/.ssh" *** ESCALATION ***
CONTROL metadata grants ~/.ssh + user denies -> stays "!~/.ssh" (correct, no flip)
CONTROL metadata !~/.ssh, no user override   -> saved "" (correct)
```
`X = /` yields `filesystems=/` — read-write access to the **entire host filesystem** (equivalent to or
worse than `filesystem=host`): full sandbox escape. Other high-value targets: `~/.ssh` (key theft),
`~/.config/autostart` (persistence / code execution at login), `~/.local/share/flatpak/overrides`
(pivot to rewrite EVERY app's sandbox → arbitrary-command chain).

**Concrete attack chain (fully attacker-orchestrated; one natural user action):**
1. Malicious app **v1** ships metadata `[Context]\nfilesystems=/` (or `~/.ssh`) — a visible scary grant.
2. The security-conscious user opens Flatseal and **revokes** it → Flatseal writes `overrides/<app>` =
   `[Context]\nfilesystems=!/`. (This is exactly the tool's intended protective use.)
3. Malicious app **v2** updates its metadata to `[Context]\nfilesystems=!/` (self-negates — appears MORE
   trustworthy: "we dropped the filesystem requirement"). Now metadata `!/` AND user override `!/`.
4. The user makes ANY later change to that app in Flatseal (toggle network, add an env var, anything).
   → the override is silently rewritten to `filesystems=/`. The UI still shows nothing. The app now has
   full host read-write access, against the user's explicit revocation.

**Severity: HIGH.** Silent, persistent, and it defeats the exact security guarantee Flatseal exists to
provide. Precondition (user override and metadata both carry `!X` for the same X) is reliably reachable
via the v1-grant → user-revoke → v2-self-negate sequence above. Verdict CONFIRMED (root-cause logic and
end-to-end pipeline reproduced independently in node).

**Fix:** in `removedOriginals` add `.filter(p => !this.constructor.isOverriden(this._overrides, p))` and
skip the `negate` mapping when `isNegated(p)` (removing a metadata self-negation should CLEAR the entry,
never grant it).

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

**Input is attacker-controlled:** verified against the REAL installed `libappstream.so.5` (v1.0.2):
AppStream parses the XML `timestamp` attribute and clamps it to `INT64_MAX` = 9223372036854775807.
Even clamped, `INT64_MAX * 1000 ≈ 9.2e21 ms` ≫ JS Date's ±8.64e15 range, so `toISOString()` still
throws. `<release timestamp="99999999999999999999">` in the malicious app's bundle is sufficient (any
timestamp whose seconds*1000 exceeds 8.64e15 ms, i.e. ≥ 8,640,000,000,001 s, triggers it).

**Reachability / impact (corrected — NOT a SIGABRT):** the throwing block is NOT wrapped in try/catch
(only `metadata.parse_file` is). `getAppDataForAppId` is called from `getAll()` (`applications.js:375`)
inside a `.map` that iterates EVERY installed app, called from `window.js:147 _setupApplications()` (no
try/catch) ← `_setup` ← `_init` ← `new FlatsealWindow()` in `application.js:107 vfunc_activate`.

IMPORTANT accuracy note: this GNOME 50 / GJS runtime does NOT hard-crash on an uncaught JS exception.
GJS catches exceptions at every C→JS boundary (vfuncs, signal handlers, timeout/idle callbacks), logs
`JS ERROR: RangeError…` at `G_LOG_LEVEL_CRITICAL`, and continues (verified in gjs source:
`gi/function.cpp:380-404`, `gi/value.cpp:393-406`, `gjs/jsapi-util.cpp:556-605`; a CRITICAL is fatal only
under `G_DEBUG=fatal-criticals`, which the GNOME Platform runtime does not set). So the concrete outcome
is: `vfunc_activate` throws → logged → `this._window` stays `null` → `present()` never runs → **no window
is created; the GtkApplication has no windows and `run()` exits.** i.e. a **persistent, windowless startup
denial-of-service on Flatseal itself** — every launch fails to show a usable window, so the user cannot
manage the permissions of ANY app, for as long as the malicious app is installed. One malicious app
poisons enumeration of ALL apps. This is a functional DoS of the security tool, not a process crash.

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
(`appInfoViewer.js:76`) via `window.js:308` inside the `row-activated` signal handler (never on startup —
`getAll()` doesn't call `getMetadataForAppId`).

**Severity DOWNGRADED to LOW** (adversarial review): (1) like C1, the throw is caught-and-logged by GJS in
the signal-handler boundary — NOT a process crash — so the only effect is the info panel's runtime label
fails to populate for that one row + a logged `JS ERROR`; the app keeps running. (2) Reachability is
questionable: Flatpak itself parses this same `metadata` with GKeyFile at install/deploy time, so a file
that GLib KeyFile rejects would generally also fail Flatpak's own validation, making it hard to have a
malformed `metadata` on a legitimately installed app. Real hardening gap (asymmetric missing guard),
low practical impact. `_parseCustomInstallation` (`applications.js:124`) has the same unguarded call but
its files live in system config, not attacker-controlled.

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

### C4 — Memory-exhaustion DoS: unbounded file read of an attacker-controlled launchable/appdata file (CONFIRMED, dependency-assisted)

**Files:** Flatseal `getDesktopForAppData` (`applications.js:258-277`) / `getAppDataForAppId`
(`applications.js:294-325`) feed an attacker-controlled file path to `AppStream.Metadata.parse_file`,
which (`libappstream as-metadata.c:768-778`) reads the ENTIRE file into a `GString` with NO size cap
before libxml2/GKeyFile limits ever apply.

The attacker fully controls the bytes of their own bundle's `export/share/applications/<launchable>`
file (and their `appdata.xml`/`metainfo.xml`). By shipping a multi-GB file there and naming it as the
`<launchable>`, Flatseal's `getDesktopForAppData` — called for EVERY app during `getAll()` at startup
(`applications.js:377`) — buffers the whole file into memory → memory exhaustion / long hang, no user
interaction. Combined with the C3 traversal, `launchable` can also point at a large/endless reachable
file on the mount. Verified library behavior (agent dlopen'd the real lib); the read loop is unbounded.
Impact: startup DoS (memory/CPU), same "malicious installed app disables Flatseal" outcome as C1.

### R1 — Race: attacker-triggered metadata reload during the pre-save window silently drops the user's edit / protective negation (CONFIRMED logic flaw; PLAUSIBLE reliable exploit)

**Files:** `permissions.js` `_delayedUpdate` (275) → `_updateModels` (294, `_changesByUser++` at 303) →
`_saveOverrides` (241); monitor path `_delayMonitorsChanged` (358) → `_updateFromMonitors` (366) →
`_setup` (311); decision logic `shared.js:updateFromProxyProperty` (95-125).

**Root cause:** the persist decision is recomputed at SAVE time from the in-memory
`_originals/_globals/_overrides` singletons. `_updateFromMonitors` calls `_setup()` whenever
`_changesByUser === 0` — which is still true during the 500 ms debounce between a user toggle and its
save (the counter is incremented inside `_updateModels`, which hasn't run yet). `_setup()` does
`model.reset()` + reload from the CURRENT (attacker-swapped) `metadata`, and does NOT cancel or flush the
pending `_delayedHandlerId`. The monitor is wired to ALL events with no event-type filter (contrast
`applications.js:_changedDelayed` which gates on `TARGET_EVENTS`), so a trivial `flatpak update`/touch of
the malicious app's own `metadata` (the one monitored file the app CAN write) triggers it.

**Verified** (I independently traced `shared.js:95-125`; race agent also ported it to node): with the user
toggling Network OFF while a reload has removed `network` from `_originals`, `updateFromProxyProperty`
takes the `if (matchesDefault && !seenInGlobals && !seenInOriginals) return;` branch and never adds
`!network` → `_saveOverrides` writes an empty set → `GLib.unlink`. The protective negation is silently
discarded; the app keeps the permission the user tried to revoke. In the non-raced path `seenInOriginals`
is true so `!network` IS persisted. A reload can never fabricate a positive grant (originals are never
serialized), so the impact is specifically DROPPING user-added restrictions — precisely defeating the
tool's purpose.

**Impact tiers:** (a) deterministic lost-update: any in-flight edit (incl. `!host`, bus denials) is
discarded if a reload lands in its 500 ms window; (b) stealthy: the app retains a revoked permission and
the re-derived UI can show it as revoked. **Exploitation is probabilistic** (attacker must land a metadata
touch in the unobservable 500 ms pre-toggle-save window; continuous touching just starves the debounce, so
it must pulse) — hence CONFIRMED logic flaw / PLAUSIBLE reliable exploit. Fix: in `_updateFromMonitors`,
flush the pending save (`_processPendingUpdates`) before `_setup()`, or merge into scratch state instead
of resetting singletons under a pending edit.

Race Findings 2-5 (cross-app pending-save write, singleton cross-app leak, backup/undo cross-app write,
overrides-dir symlink TOCTOU) — REFUTED: GJS is single-threaded (no mid-callback preemption); `set appId`
flushes the pending save via `_processPendingUpdates` BEFORE reassigning `_appId`; app-switch dismisses
the undo toast (so `undo` is unreachable post-switch) and nulls `_backup`; and the overrides dir is not
attacker-writable (Flatseal alone holds `overrides:create`), so no symlink swap.

## Plausible / preconditioned

### P1 — env-var override-write relocation (`FLATPAK_USER_DIR` / `HOST_XDG_DATA_HOME`) — INTENDED CONFIG

`applications.js:88-104 _getUserPath()` returns `GLib.getenv('FLATPAK_USER_DIR')` (or, in-flatpak,
`HOST_XDG_DATA_HOME`) unvalidated; it becomes the base for `permissions.js:142 _getBaseOverridesPath`.
However these env vars are *supported configuration knobs* (Flatpak itself honours
`FLATPAK_USER_DIR`/`FLATPAK_SYSTEM_DIR`; the test suite sets them to point at fixtures —
`tests/src/testModels.js:121-122`). A sandboxed malicious app cannot set Flatseal's environment, so this
is not a real vuln under the primary threat model. Downgraded to informational.

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

## Attack surfaces noted (native-parser, dependency-side; not a Flatseal-code bug)

- **Attacker app icons → librsvg/GdkPixbuf.** `window.js:159-164 _setupApplications` calls
  `iconTheme.add_search_path(app.appThemePath)` for EVERY app (`appThemePath` = the app's own
  `…/export/share/icons`, `applications.js:196-200`), then `applicationRow.js:31 set_from_icon_name(appIconName)`
  where `appIconName` derives from the app's desktop-entry stock icon (`applications.js:283-289`). A malicious
  app ships a crafted `.svg`/`.png` matching that icon name → Flatseal renders it at startup via
  librsvg/GdkPixbuf → potential DoS (huge/pathological SVG) or exposure to any image-loader CVE. This is a
  generic "display other apps' icons" surface (shared with GNOME Software etc.), a dependency concern, not a
  Flatseal-specific defect. Reachable with no user interaction. Flagged for completeness.

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
- **AppStream XXE / external-entity file-read / SSRF — REFUTED (real-library + strace).** libappstream
  1.0.2 parses with `XML_PARSE_NOBLANKS | XML_PARSE_NONET | XML_PARSE_BIG_LINES` (`as-xml.c:1107`); it
  never sets `XML_PARSE_NOENT` or `XML_PARSE_DTDLOAD` and never overrides the entity loader. A DOCTYPE
  with `<!ENTITY xxe SYSTEM "file:///…">` yields empty content and strace shows ZERO file/socket access.
  Internal entities substitute (attacker's own literal text only). `<name>&xxe;</name>` does not leak
  files.
- **AppStream entity-bomb / deep-nesting / huge-node DoS — REFUTED.** libxml2 2.9.14 defaults
  (no `XML_PARSE_HUGE`) reject the billion-laughs bomb ("entity reference loop"), cap depth at 256, and
  cap node size ("Huge input lookup") — all clean GErrors, no OOM/stack-overflow.
- **Desktop-entry parse of an arbitrary (C3-traversed) file crashing — REFUTED.** `parse_file(…,
  DESKTOP_ENTRY)` → `g_key_file_load_from_data`; tested against the real lib with ELF binaries, NUL-laden
  blobs, /etc/passwd, 50k groups → clean GError, no assert/abort/segv/hang. The C3 traversal only leaks a
  symbolic icon name if the target file already is a valid `[Desktop Entry]`.

## Ruled out / blocked

(none yet)
