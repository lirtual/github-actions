# Optional UU Remote Lite host on the disposable GitHub-hosted Windows Runner.
# Only the existing interactive Runner account may read its short-lived credentials.
# Refresh is executed by the existing Session hold process, on the same desktop.
param([switch]$Refresh)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'UU Lite startup requires a disposable GitHub-hosted Windows Runner'
}
$Binary = Join-Path $env:RUNNER_TEMP 'GameViewerLite-session.exe'
$Dir = Join-Path $env:LOCALAPPDATA 'session-actions'
$CredentialPath = Join-Path $Dir 'uu-remote.json'
$Ready = $false
$Failure = 'capture_failed'

try {
    if (-not $Refresh) {
        $Channel = Invoke-WebRequest -UseBasicParsing -TimeoutSec 20 'https://adl.netease.com/d/g/uuremote/c/greengw/js'
        $Link = [regex]::Match($Channel.Content, 'var\s+pc_link\s*=\s*"([^"]+)"')
        if (-not $Link.Success) { throw 'Official UU Lite download channel unavailable' }
        $Url = [uri]$Link.Groups[1].Value
        if ($Url.Scheme -ne 'https' -or $Url.Host -notmatch '^a[0-9]+\.gdl\.netease\.com$' -or
            [IO.Path]::GetFileName($Url.AbsolutePath) -notmatch '^GameViewerLite_[a-zA-Z0-9_.-]+\.exe$') {
            throw 'Unexpected UU Lite download origin'
        }
        & curl.exe --fail --location --silent --show-error --retry 2 --retry-all-errors --retry-delay 2 --max-time 90 --proto '=https' --proto-redir '=https' --output $Binary $Url.AbsoluteUri
        if ($LASTEXITCODE -ne 0) { throw 'Official UU Lite download failed' }
        $Signature = Get-AuthenticodeSignature -FilePath $Binary
        if ($Signature.Status -ne 'Valid' -or
            $Signature.SignerCertificate.Subject -notlike '*NetEase (Hangzhou) Network Co., Ltd*') {
            throw 'UU Lite publisher signature invalid'
        }
        Start-Process -FilePath $Binary | Out-Null
        Start-Sleep -Seconds 20
    }
    $SessionId = (Get-Process -Id $PID).SessionId
    $Failure = 'process_missing'
    $Processes = @(Get-Process -Name GameViewerLite,GameViewerLiteInner,GameViewerLite-session -ErrorAction SilentlyContinue |
        Where-Object { $_.SessionId -eq $SessionId })
    if ($Processes.Count -eq 0) { throw 'UU Lite process missing' }

    # Process.MainWindowHandle is zero for tray-hidden windows. Enumerate actual
    # top-level handles owned by the approved UU processes in this Session.
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class UULiteWindows {
    private delegate bool WindowCallback(IntPtr window, IntPtr param);
    [DllImport("user32.dll")] private static extern bool EnumWindows(WindowCallback callback, IntPtr param);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint pid);
    public static IntPtr[] ForPids(int[] pids) {
        var allowed = new HashSet<int>(pids);
        var found = new List<IntPtr>();
        WindowCallback callback = (window, param) => {
            uint pid;
            GetWindowThreadProcessId(window, out pid);
            if (allowed.Contains((int)pid)) found.Add(window);
            return true;
        };
        if (!EnumWindows(callback, IntPtr.Zero)) throw new InvalidOperationException("UU window enumeration failed");
        return found.ToArray();
    }
}
'@ -ErrorAction Stop
    $Failure = 'window_unavailable'
    $Handles = [UULiteWindows]::ForPids([int[]]@($Processes | ForEach-Object Id))
    if ($Handles.Count -eq 0) { throw 'UU Lite top-level window missing' }

    Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes -ErrorAction Stop
    $Failure = 'code_unavailable'
    $Pairs = @()
    foreach ($Handle in $Handles) {
        try {
            $Root = [System.Windows.Automation.AutomationElement]::FromHandle($Handle)
            if (-not $Root) { continue }
            $Items = $Root.FindAll([System.Windows.Automation.TreeScope]::Descendants,
                [System.Windows.Automation.Condition]::TrueCondition)
            $IdLabel = $false
            $CodeLabel = $false
            $Ids = @()
            $Codes = @()
            foreach ($Item in $Items) {
                $Name = [string]$Item.Current.Name
                if ($Name -match '(?i)设备.{0,3}(ID|编号)|device.{0,3}id') { $IdLabel = $true }
                if ($Name -match '验证码|verification code') { $CodeLabel = $true }
                if ($Item.Current.ControlType.ProgrammaticName -ne 'ControlType.Text') { continue }
                $Normalized = [regex]::Replace($Name.Trim(), '[\s\-–—]', '')
                if ($Normalized -match '^[0-9]{9}$') {
                    $Ids += @{ Element = $Item; Value = $Normalized }
                }
                if ($Normalized -match '^(?=.*[0-9])(?=.*[A-Za-z])[A-Za-z0-9]{8}$') {
                    $Codes += @{ Element = $Item; Value = $Normalized }
                }
            }
            if ($IdLabel -and $CodeLabel -and $Ids.Count -eq 1 -and $Codes.Count -eq 1) {
                $Pairs += @{ Id = $Ids[0]; Code = $Codes[0] }
            }
        } catch {
            # A window may close or cease exposing UIA during a remote disconnect.
            # Never publish partial or inferred credentials.
            continue
        }
    }
    if ($Pairs.Count -ne 1) { throw 'UU Lite connection data not uniquely accessible' }
    Start-Sleep -Seconds 2
    $Failure = 'code_unstable'
    $IdAgain = [regex]::Replace(([string]$Pairs[0].Id.Element.Current.Name).Trim(), '[\s\-–—]', '')
    $CodeAgain = [regex]::Replace(([string]$Pairs[0].Code.Element.Current.Name).Trim(), '[\s\-–—]', '')
    if ($IdAgain -cne $Pairs[0].Id.Value -or $CodeAgain -cne $Pairs[0].Code.Value) {
        throw 'UU Lite connection data changed during capture'
    }

    New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Acl = Get-Acl -LiteralPath $Dir
    $Acl.SetAccessRuleProtection($true, $false)
    $Rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $Identity.User, [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow)
    $Acl.SetAccessRule($Rule)
    Set-Acl -LiteralPath $Dir -AclObject $Acl
    $Failure = 'write_failed'
    $Json = [ordered]@{
        status = 'ready'
        device_id = $Pairs[0].Id.Value
        verification_code = $Pairs[0].Code.Value
    } | ConvertTo-Json -Compress
    # Avoid needless writes while the code is unchanged; replace atomically when it rotates.
    if ($Refresh -and (Test-Path -LiteralPath $CredentialPath -PathType Leaf) -and
        [IO.File]::ReadAllText($CredentialPath) -ceq $Json) {
        $Ready = $true
        return
    }
    $Temp = Join-Path $Dir ('uu-' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllText($Temp, $Json, [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $Temp -Destination $CredentialPath -Force
    } finally {
        Remove-Item -LiteralPath $Temp -Force -ErrorAction SilentlyContinue
    }
    $Ready = $true
    if (-not $Refresh) {
        Write-Output 'UU Lite is running; short-lived credentials saved for private SSH access'
    }
} finally {
    if (-not $Ready) {
        # Fail closed: never advertise a code that may have rotated. Keep a
        # private, secret-free explanation instead of an unexplained missing file.
        Remove-Item -LiteralPath $CredentialPath -Force -ErrorAction SilentlyContinue
        if ($Refresh -and (Test-Path -LiteralPath $Dir -PathType Container)) {
            $StatusTemp = Join-Path $Dir ('uu-' + [guid]::NewGuid().ToString('N') + '.tmp')
            try {
                $Status = [ordered]@{
                    status = 'unavailable'
                    reason = $Failure
                } | ConvertTo-Json -Compress
                [IO.File]::WriteAllText($StatusTemp, $Status, [Text.UTF8Encoding]::new($false))
                Move-Item -LiteralPath $StatusTemp -Destination $CredentialPath -Force
            } catch {
                # Never disrupt the existing Session hold, SSH or RDP.
            } finally {
                Remove-Item -LiteralPath $StatusTemp -Force -ErrorAction SilentlyContinue
            }
        }
        if (-not $Refresh) {
            Get-Process -Name GameViewerLite,GameViewerLiteInner,GameViewerLite-session -ErrorAction SilentlyContinue |
                Stop-Process -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $Binary -Force -ErrorAction SilentlyContinue
        }
    }
}
