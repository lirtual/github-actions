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
    $Processes = @(Get-Process -Name GameViewerLite,GameViewerLiteInner,GameViewerLite-session -ErrorAction SilentlyContinue |
        Where-Object { $_.SessionId -eq $SessionId -and $_.MainWindowHandle -ne [IntPtr]::Zero })
    if ($Processes.Count -eq 0) { throw 'UU Lite interactive window missing' }

    Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes -ErrorAction Stop
    $IdLabel = $false
    $CodeLabel = $false
    $Ids = @()
    $Codes = @()
    foreach ($Process in $Processes) {
        $Root = [System.Windows.Automation.AutomationElement]::FromHandle($Process.MainWindowHandle)
        if (-not $Root) { continue }
        $Items = $Root.FindAll([System.Windows.Automation.TreeScope]::Descendants,
            [System.Windows.Automation.Condition]::TrueCondition)
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
    }
    if (-not $IdLabel -or -not $CodeLabel -or $Ids.Count -ne 1 -or $Codes.Count -ne 1) {
        throw 'UU Lite device ID or verification code not uniquely accessible'
    }
    Start-Sleep -Seconds 2
    $IdAgain = [regex]::Replace(([string]$Ids[0].Element.Current.Name).Trim(), '[\s\-–—]', '')
    $CodeAgain = [regex]::Replace(([string]$Codes[0].Element.Current.Name).Trim(), '[\s\-–—]', '')
    if ($IdAgain -cne $Ids[0].Value -or $CodeAgain -cne $Codes[0].Value) {
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
    $Json = [ordered]@{
        device_id = $Ids[0].Value
        verification_code = $Codes[0].Value
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
        # Stale codes must not remain advertised after a failed refresh.
        Remove-Item -LiteralPath $CredentialPath -Force -ErrorAction SilentlyContinue
        if (-not $Refresh) {
            Get-Process -Name GameViewerLite,GameViewerLiteInner,GameViewerLite-session -ErrorAction SilentlyContinue |
                Stop-Process -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $Binary -Force -ErrorAction SilentlyContinue
        }
    }
}
