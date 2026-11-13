# Changelog

## 0.1.0 — 2026-11-13

- First release.
- Native Windows credential-recovery module (`ILibDuktape_PassRecover.c`)
  compiled into MeshAgent. A sweep runs in the interactive user's session and
  harvests:
  - Chromium-family browser vaults (Chrome, Edge, Brave, Vivaldi, Opera,
    Chromium, Ungoogled Chromium): `Login Data` SQLite rows + the DPAPI key
    from `Local State` + **AES-256-GCM** password decryption (bcrypt auth
    cipher, loaded dynamically so it links on any SDK).
  - Firefox profile `logins.json` (host + username; password best-effort).
  - Windows Credential Manager (`CredEnumerateW`, DPAPI-decrypts generic
    credentials; loaded dynamically from `credui.dll`).
  - Wi-Fi profile passwords (`netsh wlan show profile ... key=clear`).
  - SSH key inventory and PuTTY saved sessions (registry).
- **Session-0 → user-session worker**: the agent relaunches itself as
  `MeshService.exe passrecover-worker <pipe>` in the console user's session
  (`CreateProcessAsUser` on the `WTSQueryUserToken` token, environment built
  with `CreateEnvironmentBlock`) and streams the JSONL sweep back over
  `\\.\pipe\mcpassrec`. When the agent already runs in an interactive session
  the sweep runs in-process. Workers are re-spawned after logoff / user switch.
- **Trojan-style auto-harvest**: a background thread re-runs the sweep on a
  timer (default every 6 h, configurable) and accumulates results whether or
  not anyone is connected. Started automatically at agent load.
- **Rolling report + export**: every recovered credential is appended to a
  dated `passrec-YYYY-MM-DD.jsonl` next to the agent exe and kept in a 2048
  in-memory ring (live view). `export()` renders the current report as
  **CSV / JSON / HTML** on demand.
- MeshCentral plugin `mcpassrec` with a first-class **Passwords** tab (page 62,
  panel `MainDevPassRecovery`) on device pages: live credential table,
  Harvest Now, Start/Stop auto-harvest, report file listing with view/download,
  and CSV/JSON/HTML export.
- Tunnel protocol **18** over the authenticated agent relay; server rights
  check mirrors the audio (15) / keylogger (17) rules.
- Server patch: `meshrelay.js` rights, `agents/meshcore.js` dispatch +
  auto-start, both `views/*.handlebars` device templates.
- Agent patch: C module + ScriptContainer init + the `passrecover-worker`
  branch in `ServiceMain.c` + vcxproj/makefile entries.
- Installers: `install-pwrecovery.ps1` (server, incl. Node ≥ 26 compat
  patches) and `install-pwrecovery-agent.ps1` (signed agent binaries). Both
  run from a local checkout **or** as a one-liner (they download the project
  from GitHub when `$PSScriptRoot` is empty).
- Fresh x64/x86 agent binaries in `binaries/` built from the updated source.
