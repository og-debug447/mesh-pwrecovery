# Diagnostics for the passrecover worker launch failure.
# Run as SYSTEM (e.g. via MeshCentral runcommands). Replicates the exact
# CreateProcessAsUserW sequence from ILibDuktape_PassRecover.c and reports
# GetLastError for each variant (with/without user env block, target exe).
$ErrorActionPreference = 'Continue'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
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
  public static extern bool CreateProcessAsUserW(IntPtr token, string app, string cmd, IntPtr sa, IntPtr pa, bool inherit, uint flags, IntPtr env, string wd, ref STARTUPINFOW si, out PROCESS_INFORMATION pi);
}
'@

function WinErr() { [Runtime.InteropServices.Marshal]::GetLastWin32Error() }

$out = @()
$out += 'whoami=' + (whoami)
$sess = [DiagW]::WTSGetActiveConsoleSessionId()
$out += 'console_session=' + $sess

$token = [IntPtr]::Zero
if (-not [DiagW]::WTSQueryUserToken($sess, [ref]$token)) { $out += 'WTSQueryUserToken FAILED err=' + (WinErr); return ($out -join "`r`n") }
$out += 'WTSQueryUserToken OK'

$dup = [IntPtr]::Zero
if (-not [DiagW]::DuplicateTokenEx($token, 0x1FFFFF, [IntPtr]::Zero, 2, 1, [ref]$dup)) { $out += 'DuplicateTokenEx FAILED err=' + (WinErr); return ($out -join "`r`n") }
[void][DiagW]::SetTokenInformation($dup, 12, [ref]$sess, 4)
$out += 'DuplicateTokenEx+SetTokenInformation OK'

$env = [IntPtr]::Zero
$envOk = [DiagW]::CreateEnvironmentBlock([ref]$env, $dup, 0)
$out += 'CreateEnvironmentBlock=' + $envOk + $(if (-not $envOk) { ' err=' + (WinErr) } else { '' })

$exe = 'C:\Program Files\Mesh Agent\MeshAgent.exe'
$wd  = 'C:\Program Files\Mesh Agent'
$cmdA = '"' + $exe + '" passrecover-worker'

function TryCreate([IntPtr]$envPtr, [string]$label, [string]$app, [string]$cmd) {
  $si = New-Object DiagW+STARTUPINFOW
  $si.cb = [Runtime.InteropServices.Marshal]::SizeOf([type]'DiagW+STARTUPINFOW')
  $si.dwFlags = 1   # STARTF_USESHOWWINDOW
  $si.wShowWindow = 0  # SW_HIDE
  $pi = New-Object DiagW+PROCESS_INFORMATION
  $ok = [DiagW]::CreateProcessAsUserW($dup, $app, $cmd, [IntPtr]::Zero, [IntPtr]::Zero, $false, 0, $envPtr, $wd, [ref]$si, [ref]$pi)
  $line = 'CREATE[' + $label + '] ok=' + $ok + ' err=' + (WinErr)
  if ($ok) {
    Start-Sleep -Seconds 3
    $line += ' pid=' + $pi.dwProcessId
  }
  $line
}

$out += TryCreate $env 'userenv+agent' $exe $cmdA
$out += TryCreate [IntPtr]::Zero 'noenv+agent' $exe $cmdA
$out += TryCreate $env 'userenv+cmd' 'C:\Windows\System32\cmd.exe' 'C:\Windows\System32\cmd.exe /c exit 7'
$out += TryCreate [IntPtr]::Zero 'noenv+cmd' 'C:\Windows\System32\cmd.exe' 'C:\Windows\System32\cmd.exe /c exit 7'
$out += 'diagnostics complete'
$out -join "`r`n"
