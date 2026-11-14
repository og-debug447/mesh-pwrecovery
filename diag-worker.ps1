# Diagnostics for the passrecover worker launch failure (v3).
# Run as SYSTEM via MeshCentral runcommands:
#   Set-ExecutionPolicy -Scope Process Bypass; & C:\Windows\TEMP\dw.ps1
# Replicates the exact CreateProcessAsUserW sequence from
# ILibDuktape_PassRecover.c, dumps the CreateEnvironmentBlock block
# (byte-copy, no IntPtr arithmetic), and reports GetLastError for
# five launch variants. Full dump goes to C:\Windows\TEMP\dw-out.txt.
$ErrorActionPreference = 'Continue'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public class DiagW {
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  public struct STARTUPINFOW {
    public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
    public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute;
    public int dwFlags; public short wShowWindow; public short cbReserved2;
    public IntPtr lpszCommandLine; public int Reserved2;
    public IntPtr hStdInput, hStdOutput, hStdError;
  }
  [StructLayout(LayoutKind.Sequential)]
  public struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

  [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
  [DllImport("wtsapi32.dll", SetLastError=true)] public static extern bool WTSQueryUserToken(uint sid, out IntPtr token);
  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool DuplicateTokenEx(IntPtr e, int d, IntPtr s, int i, int t, out IntPtr n);
  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool SetTokenInformation(IntPtr t, int c, ref uint i, int l);
  [DllImport("userenv.dll", SetLastError=true)] public static extern bool CreateEnvironmentBlock(out IntPtr env, IntPtr token, int flags);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool GetUserNameW(StringBuilder name, ref int len);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool CreateProcessAsUserW(IntPtr token, string app, string cmd, IntPtr sa, IntPtr pa, bool inherit, uint flags, IntPtr env, string wd, ref STARTUPINFOW si, out PROCESS_INFORMATION pi);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
}
'@

$zero = [IntPtr]::Zero
function WinErr() { [Runtime.InteropServices.Marshal]::GetLastWin32Error() }

$out = @()
$full = @()
$full += 'whoami=' + (whoami)
$sess = [DiagW]::WTSGetActiveConsoleSessionId()
$full += 'console_session=' + $sess

$token = $zero
if (-not [DiagW]::WTSQueryUserToken($sess, [ref]$token)) { $full += 'WTSQueryUserToken FAILED err=' + (WinErr); $full += 'diagnostics complete (early)'; return (($out + $full) -join "`r`n") }
$dup = $zero
if (-not [DiagW]::DuplicateTokenEx($token, 0x1FFFFF, $zero, 2, 1, [ref]$dup)) { $full += 'DuplicateTokenEx FAILED err=' + (WinErr); $full += 'diagnostics complete (early)'; return (($out + $full) -join "`r`n") }
[void][DiagW]::SetTokenInformation($dup, 12, [ref]$sess, 4)
$who = New-Object System.Text.StringBuilder 256
$wlen = 256
[void][DiagW]::GetUserNameW($who, [ref]$wlen)
$full += 'token_user=' + $who.ToString()

$env = $zero
$envOk = [DiagW]::CreateEnvironmentBlock([ref]$env, $dup, 0)
$full += 'CreateEnvironmentBlock=' + $envOk + $(if (-not $envOk) { ' err=' + (WinErr) } else { '' })

if ($envOk -and $env -ne $zero) {
  $bytes = New-Object byte[] 32768
  [Runtime.InteropServices.Marshal]::Copy($env, $bytes, 0, 32768)
  $blkBytes = 0
  for ($i = 0; $i -lt 32764; $i += 2) {
    if ($bytes[$i] -eq 0 -and $bytes[$i+1] -eq 0 -and $bytes[$i+2] -eq 0 -and $bytes[$i+3] -eq 0) { $blkBytes = ($i / 2 + 1) * 2; break }
  }
  $full += 'env_block_bytes=' + $blkBytes
  $s = [System.Text.Encoding]::Unicode.GetString($bytes)
  $parts = $s -split "`0"
  $n = 0
  foreach ($e in $parts) {
    if ($n -gt 400) { $full += 'ENV: >400 entries (stopping)'; break }
    if ($e -eq '') {
      $full += ('ENV[{0}] EMPTY-ENTRY' -f $n)
      $n++
      continue
    }
    $eqi = $e.IndexOf('=')
    $flag = 'ok'
    if ($eqi -lt 0) { $flag = 'NO-EQ!' }
    elseif ($eqi -eq 0) { $flag = 'EMPTY-NAME!' }
    $name = $e
    $vlen = $e.Length
    if ($eqi -gt 0) { $name = $e.Substring(0, $eqi); $vlen = $e.Length - $eqi - 1 }
    $line = ('ENV[{0}] {1} name=[{2}] vlen={3}' -f $n, $flag, $name, $vlen)
    if ($vlen -gt 0 -and $eqi -gt 0) { $val = $e.Substring($eqi + 1); if ($val.Length -gt 48) { $val = $val.Substring(0, 48) + '...' }; $line += ' val=[' + $val + ']' }
    $full += $line
    $n++
  }
  $full += 'ENV: total parts=' + $n
}

$exe = 'C:\Program Files\Mesh Agent\MeshAgent.exe'
$wd  = 'C:\Program Files\Mesh Agent'
$cmdA = '"' + $exe + '" passrecover-worker'
$cmdC = 'C:\Windows\System32\cmd.exe /c exit 7'

$miniBytes = [System.Text.Encoding]::Unicode.GetBytes('OS=Windows_NT' + [char]0 + [char]0)
$miniPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($miniBytes.Length)
[Runtime.InteropServices.Marshal]::Copy($miniBytes, 0, $miniPtr, $miniBytes.Length)

function TryCreate([IntPtr]$envPtr, [string]$label, [string]$app, [string]$cmd) {
  $si = New-Object DiagW+STARTUPINFOW
  $si.cb = [Runtime.InteropServices.Marshal]::SizeOf([type]'DiagW+STARTUPINFOW')
  $si.dwFlags = 1
  $si.wShowWindow = 0
  $pi = New-Object DiagW+PROCESS_INFORMATION
  $ok = [DiagW]::CreateProcessAsUserW($dup, $app, $cmd, $zero, $zero, $false, 0, $envPtr, $wd, [ref]$si, [ref]$pi)
  $line = 'CREATE[' + $label + '] ok=' + $ok + ' err=' + (WinErr)
  if ($ok) {
    $line += ' pid=' + $pi.dwProcessId
    if ($pi.hProcess -ne $zero) { [void][DiagW]::CloseHandle($pi.hProcess) }
    if ($pi.hThread -ne $zero) { [void][DiagW]::CloseHandle($pi.hThread) }
    Start-Sleep -Seconds 2
  }
  $line
}

$r1 = TryCreate $env 'userenv+agent' $exe $cmdA
$full += $r1
$r2 = TryCreate $zero 'noenv+agent' $exe $cmdA
$full += $r2
$r3 = TryCreate $env 'userenv+cmd' 'C:\Windows\System32\cmd.exe' $cmdC
$full += $r3
$r4 = TryCreate $zero 'noenv+cmd' 'C:\Windows\System32\cmd.exe' $cmdC
$full += $r4
$r5 = TryCreate $miniPtr 'minienv+cmd' 'C:\Windows\System32\cmd.exe' $cmdC
$full += $r5
[Runtime.InteropServices.Marshal]::FreeHGlobal($miniPtr)
$full += 'diagnostics complete'

$full | Out-File C:\Windows\TEMP\dw-out.txt -Encoding utf8
$full -join "`r`n"
