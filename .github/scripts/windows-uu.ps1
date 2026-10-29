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
        $UiStartupWatch = [Diagnostics.Stopwatch]::StartNew()
        Start-Process -FilePath $Binary | Out-Null
    }
    $SessionId = (Get-Process -Id $PID).SessionId
    # Process.MainWindowHandle can be zero for tray-hidden windows; enumerate
    # top-level windows owned by approved UU processes in this desktop Session.
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
    Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes -ErrorAction Stop
    # Poll the actual UU UI for unique ID/code controls instead of sleeping
    # a fixed 20 seconds. The refresh path performs one immediate scan.
    $ProbeDeadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $Failure = 'process_missing'
        $Processes = @(Get-Process -Name GameViewerLite,GameViewerLiteInner,GameViewerLite-session -ErrorAction SilentlyContinue |
            Where-Object { $_.SessionId -eq $SessionId })
        $Pairs = @()
        if ($Processes.Count -gt 0) {
            $Failure = 'window_unavailable'
            $Handles = [UULiteWindows]::ForPids([int[]]@($Processes | ForEach-Object Id))
            if ($Handles.Count -gt 0) {
                $Failure = 'code_unavailable'
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
                        $ShareButtons = @()
                        $AllButtons = @()
                        foreach ($Item in $Items) {
                            $Name = [string]$Item.Current.Name
                            if ($Name -match '(?i)设备.{0,3}(ID|编号)|device.{0,3}id') { $IdLabel = $true }
                            if ($Name -match '验证码|verification code') { $CodeLabel = $true }
                            if ($Item.Current.ControlType.ProgrammaticName -eq 'ControlType.Button') {
                                $AllButtons += $Item
                            }
                            if ($Name.Trim() -match '^(复制并分享|Copy( and)? Share)$') {
                                if ($Item.Current.ControlType.ProgrammaticName -eq 'ControlType.Button') {
                                    $ShareButtons += $Item
                                }
                            }
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
                            # Some UU Lite builds expose two unnamed native Buttons.
                            # Identify only the unique button aligned to the verified code
                            # on its right, not an arbitrary screen coordinate or label.
                            if ($ShareButtons.Count -eq 0 -and $AllButtons.Count -eq 2) {
                                $CodeBox = $Codes[0].Element.Current.BoundingRectangle
                                if ($CodeBox.Width -gt 40 -and $CodeBox.Height -gt 10) {
                                    $Adjacent = @(
                                        foreach ($Button in $AllButtons) {
                                            $Box = $Button.Current.BoundingRectangle
                                            $DistanceY = [Math]::Abs(
                                                ($Box.Top + $Box.Bottom) / 2 -
                                                ($CodeBox.Top + $CodeBox.Bottom) / 2)
                                            if ($Button.Current.IsEnabled -and
                                                $Box.Left -ge $CodeBox.Right -and
                                                $Box.Width -ge 60 -and $Box.Width -le 250 -and
                                                $Box.Height -ge 18 -and $Box.Height -le 70 -and
                                                $DistanceY -le 45) { $Button }
                                        }
                                    )
                                    if ($Adjacent.Count -eq 1) { $ShareButtons = @($Adjacent[0]) }
                                }
                            }
                            $Pairs += @{ Id = $Ids[0]; Code = $Codes[0]; ShareButtons = $ShareButtons }
                        }
                    } catch {
                        # A window may close or cease exposing UIA during a remote disconnect.
                        # Never publish partial or inferred credentials.
                        continue
                    }
                }
            }
        }
        if ($Pairs.Count -eq 1) { break }
        if ($Refresh -or [DateTime]::UtcNow -ge $ProbeDeadline) {
            throw 'UU Lite connection data not uniquely accessible'
        }
        Start-Sleep -Seconds 1
    } while ($true)
    Start-Sleep -Seconds 2
    $Failure = 'code_unstable'
    $IdAgain = [regex]::Replace(([string]$Pairs[0].Id.Element.Current.Name).Trim(), '[\s\-–—]', '')
    $CodeAgain = [regex]::Replace(([string]$Pairs[0].Code.Element.Current.Name).Trim(), '[\s\-–—]', '')
    if ($IdAgain -cne $Pairs[0].Id.Value -or $CodeAgain -cne $Pairs[0].Code.Value) {
        throw 'UU Lite connection data changed during capture'
    }

    # An invite link is an optional credential, obtained from UU's own
    # "Copy and share" button. Never infer it from device ID or code.
    # Invoke ONLY during initial startup: repeated 30s refreshes must not
    # interrupt the interactive owner's clipboard.
    $ShareUrl = $null
    $InvitePattern = 'https://uuyc\.163\.com/invite/[0-9a-fA-F]{32}(?![A-Za-z0-9/?#])'
    if (-not $Refresh -and $Pairs[0].ShareButtons.Count -eq 1) {
        $OriginalClipboard = $null
        $CopiedText = $null
        $ClipboardPrimed = $false
        $Marker = 'uu-share-' + [guid]::NewGuid().ToString('N')
        try {
            $OriginalClipboard = [string](Get-Clipboard -Raw -ErrorAction Stop)
            if ($OriginalClipboard.Length -gt 8192) { throw 'Existing clipboard too large' }
            # Hosted Runner desktop can report ClipboardSequenceNumber=0.
            # A one-shot random marker proves the button produced NEW text.
            Set-Clipboard -Value $Marker -ErrorAction Stop
            $ClipboardPrimed = $true
            if ([string](Get-Clipboard -Raw -ErrorAction Stop) -cne $Marker) {
                throw 'Clipboard marker unavailable'
            }
            $Invoke = $Pairs[0].ShareButtons[0].GetCurrentPattern(
                [System.Windows.Automation.InvokePattern]::Pattern)
            $Invoke.Invoke()
            for ($i = 0; $i -lt 5; $i++) {
                Start-Sleep -Milliseconds 200
                $Current = [string](Get-Clipboard -Raw -ErrorAction Stop)
                if ($Current -cne $Marker) {
                    $CopiedText = $Current
                    break
                }
            }
            if ($null -ne $CopiedText) {
                $Links = @([regex]::Matches($CopiedText, $InvitePattern))
                if ($Links.Count -eq 1) {
                    $ShareUrl = $Links[0].Value
                }
            }
        } catch {
            # Never log exception details, previous clipboard, URL or code.
        } finally {
            # Restore only when still holding our marker/copied text. Do not
            # overwrite a concurrent clipboard update by the human owner.
            if ($ClipboardPrimed) {
                try {
                    $Now = [string](Get-Clipboard -Raw -ErrorAction Stop)
                    if ($Now -ceq $Marker -or
                        ($null -ne $CopiedText -and $Now -ceq $CopiedText)) {
                        Set-Clipboard -Value $OriginalClipboard -ErrorAction Stop
                    }
                } catch { }
            }
        }
    }
    if ($Refresh -and (Test-Path -LiteralPath $CredentialPath -PathType Leaf)) {
        try {
            $Previous = [IO.File]::ReadAllText($CredentialPath) | ConvertFrom-Json
            if ($Previous.status -eq 'ready' -and
                $Previous.device_id -ceq $Pairs[0].Id.Value -and
                $Previous.verification_code -ceq $Pairs[0].Code.Value -and
                $Previous.share_url -is [string] -and
                $Previous.share_url -cmatch ('^' + $InvitePattern + '$')) {
                $ShareUrl = $Previous.share_url
            }
        } catch { }
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
    $Payload = [ordered]@{
        status = 'ready'
        device_id = $Pairs[0].Id.Value
        verification_code = $Pairs[0].Code.Value
    }
    if ($ShareUrl) { $Payload.share_url = $ShareUrl }
    $Json = $Payload | ConvertTo-Json -Compress
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
        Write-Output ('UU Lite UI credentials ready after {0:N1}s' -f $UiStartupWatch.Elapsed.TotalSeconds)
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
