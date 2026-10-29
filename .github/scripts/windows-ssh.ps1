# Windows GitHub-hosted Runner: password-only SSH for the existing job account.
# This account is an administrator. SSH must remain reachable only through Tailscale.
$ErrorActionPreference = 'Stop'
$StartupWatch = [Diagnostics.Stopwatch]::StartNew()

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Username = [Environment]::UserName
$Account = Get-LocalUser -Name $Username -ErrorAction Stop
$IsAdmin = ([Security.Principal.WindowsPrincipal]::new($Identity)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $Account.Enabled -or $Account.SID.Value -ne $Identity.User.Value -or -not $IsAdmin) {
    throw 'Expected an enabled local administrator as the Windows Runner account'
}
if ($Username -notmatch '^[A-Za-z][A-Za-z0-9_-]{0,31}$' -or
    $Username -in @('Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount')) {
    throw 'Unexpected Windows Runner account'
}

$Password = $env:SESSION_SYSTEM_PASSWORD
if ([string]::IsNullOrEmpty($Password) -or $Password.Length -lt 8 -or
    $Password.Contains([char]10) -or $Password.Contains([char]13)) {
    throw 'SESSION_SYSTEM_PASSWORD must contain at least 8 characters on one line'
}
# This job uses a disposable GitHub-hosted Windows Runner. Do not alter the
# local account policy on any persistent/self-hosted Windows machine.
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    -not (Test-Path -LiteralPath $env:RUNNER_TEMP -PathType Container)) {
    throw 'Windows password policy adjustment requires a GitHub-hosted Runner'
}
$PolicyStart = $StartupWatch.Elapsed
$PolicyFile = Join-Path $env:RUNNER_TEMP 'session-actions-password.inf'
$PolicyDb = Join-Path $env:RUNNER_TEMP 'session-actions-password.sdb'
$PolicyLog = Join-Path $env:RUNNER_TEMP 'session-actions-password.log'
@'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[System Access]
MinimumPasswordLength = 8
PasswordComplexity = 0
'@ | Set-Content -LiteralPath $PolicyFile -Encoding Ascii
try {
    & secedit.exe /configure /db $PolicyDb /cfg $PolicyFile /areas SECURITYPOLICY /log $PolicyLog /quiet
    if ($LASTEXITCODE -ne 0) { throw 'Unable to apply 8-character Windows Runner password policy' }
} finally {
    Remove-Item -LiteralPath $PolicyFile -Force -ErrorAction SilentlyContinue
}
Write-Output ('Windows SSH local password policy: {0:N1}s' -f ($StartupWatch.Elapsed - $PolicyStart).TotalSeconds)
$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
Remove-Variable Password
$env:SESSION_SYSTEM_PASSWORD = $null
Set-LocalUser -Name $Username -Password $SecurePassword -ErrorAction Stop
Remove-Variable SecurePassword

$Tailnet = @(Get-NetAdapter | Where-Object {
    $_.InterfaceDescription -match 'Tailscale' -and $_.Status -eq 'Up'
})
if ($Tailnet.Count -ne 1) { throw 'Expected one active Tailscale interface' }
$TailnetIPv4 = @(Get-NetIPAddress -InterfaceIndex $Tailnet[0].ifIndex -AddressFamily IPv4 |
    Where-Object {
        $Parts = $_.IPAddress.Split('.')
        $Parts.Count -eq 4 -and $Parts[0] -eq '100' -and
        [int]$Parts[1] -ge 64 -and [int]$Parts[1] -le 127
    })
if ($TailnetIPv4.Count -ne 1) { throw 'Expected one Tailnet IPv4 address' }
$TailnetAddress = $TailnetIPv4[0].IPAddress

$SshCapabilityStart = $StartupWatch.Elapsed
$Capability = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
if ($Capability.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null
}
Write-Output ('Windows SSH capability availability: {0:N1}s' -f ($StartupWatch.Elapsed - $SshCapabilityStart).TotalSeconds)
$ServiceStart = $StartupWatch.Elapsed
$Config = Join-Path $env:ProgramData 'ssh\sshd_config'
if (-not (Test-Path $Config)) { throw 'OpenSSH configuration missing' }
$Baseline = [IO.File]::ReadAllText($Config)
# Prepend restrictions before any default Match blocks.
$Guard = 'PasswordAuthentication yes' + [Environment]::NewLine +
    'PubkeyAuthentication no' + [Environment]::NewLine +
    'AuthenticationMethods password' + [Environment]::NewLine +
    'PermitEmptyPasswords no' + [Environment]::NewLine +
    ('AllowUsers ' + $Username.ToLowerInvariant()) + [Environment]::NewLine +
    ('ListenAddress ' + $TailnetAddress) + [Environment]::NewLine
[IO.File]::WriteAllText($Config, $Guard + $Baseline, [Text.UTF8Encoding]::new($false))
$Sshd = Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'
& $Sshd -t
if ($LASTEXITCODE -ne 0) { throw 'OpenSSH config test failed' }
$EffectiveConfig = & $Sshd -T
if ($LASTEXITCODE -ne 0 -or
    -not ($EffectiveConfig -contains 'passwordauthentication yes') -or
    -not ($EffectiveConfig -contains 'pubkeyauthentication no') -or
    -not ($EffectiveConfig -contains 'authenticationmethods password') -or
    -not ($EffectiveConfig -contains ('listenaddress ' + $TailnetAddress + ':22'))) {
    throw 'OpenSSH effective authentication or interface policy is not restricted'
}
# An already running sshd could still have the previous configuration.
if ((Get-Service sshd -ErrorAction Stop).Status -eq 'Running') {
    Stop-Service sshd -ErrorAction Stop
}
Set-Service sshd -StartupType Manual
# Disable the stock broad inbound rule before allowing only the Tailnet address.
Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue |
    Disable-NetFirewallRule
New-NetFirewallRule -Name 'SessionActionsTailscaleSSH' -DisplayName 'Session Actions Tailnet SSH' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 -LocalAddress $TailnetAddress -RemoteAddress '100.64.0.0/10' -InterfaceAlias $Tailnet[0].Name | Out-Null
Start-Service sshd -ErrorAction Stop
$Listeners = @(Get-NetTCPConnection -State Listen -LocalPort 22 -ErrorAction SilentlyContinue)
if ($Listeners.Count -ne 1 -or $Listeners[0].LocalAddress -ne $TailnetAddress) {
    throw 'OpenSSH must listen only on the assigned Tailnet IPv4 address'
}
Write-Output ('Windows SSH configuration, service and listener validation: {0:N1}s' -f ($StartupWatch.Elapsed - $ServiceStart).TotalSeconds)
Write-Output ('Windows SSH total local setup: {0:N1}s' -f $StartupWatch.Elapsed.TotalSeconds)
Write-Output 'Tailnet-restricted Windows password SSH is ready'
