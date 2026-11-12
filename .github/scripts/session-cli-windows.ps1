# Optional CLI authentication for an accepted, disposable Windows Session.
param([ValidateSet('Install', 'Activate', 'Cleanup')][string]$Mode)
$ErrorActionPreference = 'Stop'
$Root = Join-Path $HOME '.session-actions'
$Auth = Join-Path $Root 'auth'
$Prefix = Join-Path $Root 'npm'
$ProfilePath = $PROFILE.CurrentUserAllHosts

function Protect-Directory([string]$Path) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $Sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & icacls.exe $Path /inheritance:r /grant:r "*$($Sid):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to restrict Session credential directory ACL' }
}

function Remove-ProfileHook {
    if (-not (Test-Path -LiteralPath $ProfilePath)) { return }
    $Text = [IO.File]::ReadAllText($ProfilePath)
    $Pattern = '(?ms)^# session-actions login begin\r?\n.*?^# session-actions login end\r?\n?'
    $Clean = [regex]::Replace($Text, $Pattern, '')
    if ($Clean -ne $Text) {
        [IO.File]::WriteAllText($ProfilePath, $Clean, [Text.UTF8Encoding]::new($false))
    }
}

switch ($Mode) {
    'Install' {
        if (Get-Command cf -ErrorAction SilentlyContinue) {
            Write-Output 'cf command already exists; installation skipped to avoid a collision'
            break
        }
        if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue) -or -not (Get-Command node.exe -ErrorAction SilentlyContinue)) {
            Write-Output 'Optional cf CLI unavailable: Node.js/npm missing'
            break
        }
        $VersionText = (& node.exe --version).TrimStart('v')
        $Numbers = @($VersionText.Split('.') | ForEach-Object { [int]$_ })
        $Supported = ($Numbers[0] -eq 22 -and $Numbers[1] -ge 18) -or ($Numbers[0] -ge 23)
        if (-not $Supported) {
            Write-Output 'Pinned cf CLI requires a newer Node.js version'
            break
        }
        New-Item -ItemType Directory -Path $Prefix -Force | Out-Null
        $Npm = (Get-Command npm.cmd).Source
        $Output = Join-Path $env:RUNNER_TEMP 'session-cf-install.log'
        $ErrorLog = Join-Path $env:RUNNER_TEMP 'session-cf-install.err'
        try {
            $Arguments = 'install --global --prefix "' + $Prefix + '" --ignore-scripts --no-audit --no-fund cf@1.0.0-beta.14'
            $Process = Start-Process -FilePath $env:ComSpec -ArgumentList ('/d /c ""' + $Npm + '" ' + $Arguments + '"') -NoNewWindow -PassThru -RedirectStandardOutput $Output -RedirectStandardError $ErrorLog
            if (-not $Process.WaitForExit(75000)) {
                $Process.Kill($true)
                Write-Output 'Optional cf CLI installation timed out'
                break
            }
            if ($Process.ExitCode -ne 0 -or -not (Test-Path (Join-Path $Prefix 'cf.cmd'))) {
                Write-Output 'Optional cf CLI installation unavailable'
                break
            }
            & (Join-Path $Prefix 'cf.cmd') --version *> $null
            if ($LASTEXITCODE -ne 0) { Write-Output 'Optional cf CLI verification failed'; break }
            Write-Output 'Pinned cf CLI installed'
        } finally {
            Remove-Item -LiteralPath $Output, $ErrorLog -Force -ErrorAction SilentlyContinue
        }
    }
    'Activate' {
        & git config --global user.useConfigOnly true
        if ($env:GIT_USER_NAME) { & git config --global user.name $env:GIT_USER_NAME }
        else { & git config --global --unset-all user.name 2>$null }
        if ($env:GIT_USER_EMAIL) { & git config --global user.email $env:GIT_USER_EMAIL }
        else { & git config --global --unset-all user.email 2>$null }

        if ($env:GH_TOKEN -and (Get-Command gh -ErrorAction SilentlyContinue)) {
            & gh auth setup-git --hostname github.com --force *> $null
            if ($LASTEXITCODE -ne 0) {
                Write-Output 'Optional GitHub Git helper configuration unavailable'
            }
        }

        Protect-Directory $Root
        Protect-Directory $Auth
        foreach ($Name in @('github.token', 'cloudflare.token', 'cloudflare.account')) {
            Remove-Item -LiteralPath (Join-Path $Auth $Name) -Force -ErrorAction SilentlyContinue
        }
        $Encoding = [Text.UTF8Encoding]::new($false)
        if ($env:GH_TOKEN) {
            [IO.File]::WriteAllText((Join-Path $Auth 'github.token'), $env:GH_TOKEN, $Encoding)
        }
        if ($env:CLOUDFLARE_API_TOKEN) {
            [IO.File]::WriteAllText((Join-Path $Auth 'cloudflare.token'), $env:CLOUDFLARE_API_TOKEN, $Encoding)
            if ($env:CLOUDFLARE_ACCOUNT_ID) {
                [IO.File]::WriteAllText((Join-Path $Auth 'cloudflare.account'), $env:CLOUDFLARE_ACCOUNT_ID, $Encoding)
            }
        }

        $Folder = Split-Path -Parent $ProfilePath
        New-Item -ItemType Directory -Path $Folder -Force | Out-Null
        Remove-ProfileHook
        $Hook = @'
# session-actions login begin
$sessionRoot = Join-Path $HOME '.session-actions'
$sessionAuth = Join-Path $sessionRoot 'auth'
$githubFile = Join-Path $sessionAuth 'github.token'
$cloudflareFile = Join-Path $sessionAuth 'cloudflare.token'
$accountFile = Join-Path $sessionAuth 'cloudflare.account'
# Do not expose the interactive PAT to subsequent GitHub Actions steps.
if ($env:GITHUB_ACTIONS -ne 'true') {
    if (Test-Path -LiteralPath $githubFile) {
        $env:GH_TOKEN = [IO.File]::ReadAllText($githubFile)
    }
    if (Test-Path -LiteralPath $cloudflareFile) {
        $env:CLOUDFLARE_API_TOKEN = [IO.File]::ReadAllText($cloudflareFile)
        if (Test-Path -LiteralPath $accountFile) {
            $env:CLOUDFLARE_ACCOUNT_ID = [IO.File]::ReadAllText($accountFile)
        }
    }
}
$cfBin = Join-Path $sessionRoot 'npm'
if (Test-Path -LiteralPath (Join-Path $cfBin 'cf.cmd')) {
    $env:PATH = "$cfBin;$env:PATH"
}
# session-actions login end
'@
        [IO.File]::AppendAllText($ProfilePath, [Environment]::NewLine + $Hook + [Environment]::NewLine, $Encoding)

        # OpenSSH defaults to cmd.exe; switch only the disposable hosted Runner.
        # Actual SSH remote-command compatibility needs a real Session E2E.
        if ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted') {
            $Pwsh = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
            if (Test-Path -LiteralPath $Pwsh -PathType Leaf) {
                New-Item -Path 'HKLM:\SOFTWARE\OpenSSH' -Force | Out-Null
                New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value $Pwsh -PropertyType String -Force | Out-Null
                New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShellCommandOption -Value '-c' -PropertyType String -Force | Out-Null
            } else {
                Write-Output 'Optional PowerShell SSH default shell unavailable'
            }
        }
        Write-Output 'Optional Windows Session CLI activation complete'
    }
    'Cleanup' {
        Remove-ProfileHook
        if (Test-Path -LiteralPath $Auth) {
            Remove-Item -LiteralPath $Auth -Recurse -Force -ErrorAction SilentlyContinue
        }
        Write-Output 'Windows Session CLI credential material removed'
    }
}
