# Windows GitHub-hosted Runner: non-admin, key-only SSH over Tailscale.
$ErrorActionPreference = 'Stop'
$PublicKey = $env:SESSION_SSH_PUBLIC_KEY
if ($PublicKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/]{40,128}={0,3}( [^\r\n]*)?$') {
    throw 'SESSION_SSH_PUBLIC_KEY must be one valid Ed25519 public key'
}
if ($PublicKey.Contains([char]10) -or $PublicKey.Contains([char]13)) {
    throw 'Only one SSH authorized key is permitted'
}
$Tailnet = @(Get-NetAdapter | Where-Object {
    $_.InterfaceDescription -match 'Tailscale' -and $_.Status -eq 'Up'
})
if ($Tailnet.Count -ne 1) { throw 'Expected one active Tailscale interface' }

$Username = 'sessionuser'
if (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue) {
    throw 'Session SSH account already exists'
}
$Random = [Security.Cryptography.RandomNumberGenerator]::GetBytes(48)
$Password = [Convert]::ToBase64String($Random) | ConvertTo-SecureString -AsPlainText -Force
New-LocalUser -Name $Username -Password $Password -PasswordNeverExpires | Out-Null
$UserHome = Join-Path $env:SystemDrive "Users\$Username"
$Directory = Join-Path $UserHome '.ssh'
New-Item -Path $Directory -ItemType Directory -Force | Out-Null
$Keys = Join-Path $Directory 'authorized_keys'
[IO.File]::WriteAllText($Keys, $PublicKey + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
& icacls.exe $Directory '/inheritance:r' "/grant:r" "$($Username):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'SSH directory ACL failed' }
& icacls.exe $Keys '/inheritance:r' "/grant:r" "$($Username):R" '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'SSH key ACL failed' }
// Windows sshd StrictModes also validates the owner, not only the ACL.
// GitHub Runner initially creates these files as its admin account.
& icacls.exe $Keys '/setowner' $Username | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'SSH key owner update failed' }
& icacls.exe $Directory '/setowner' $Username | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'SSH directory owner update failed' }
$Capability = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
if ($Capability.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null
}
# Restrict the SSH daemon too. Prepend before default Match blocks.
$Config = Join-Path $env:ProgramData 'ssh\sshd_config'
if (-not (Test-Path $Config)) { throw 'OpenSSH configuration missing' }
$Baseline = [IO.File]::ReadAllText($Config)
$Guard = 'PasswordAuthentication no' + [Environment]::NewLine +
    'PubkeyAuthentication yes' + [Environment]::NewLine +
    'PermitEmptyPasswords no' + [Environment]::NewLine +
    'AllowUsers sessionuser' + [Environment]::NewLine +
    ('AuthorizedKeysFile "' + $Keys + '"') + [Environment]::NewLine
[IO.File]::WriteAllText($Config, $Guard + $Baseline, [Text.UTF8Encoding]::new($false))
$Sshd = Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'
& $Sshd -t
if ($LASTEXITCODE -ne 0) { throw 'OpenSSH config test failed' }
Set-Service sshd -StartupType Manual
# Disable broad stock inbound rules BEFORE opening the Tailnet-only one.
Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue |
    Disable-NetFirewallRule
New-NetFirewallRule -Name 'SessionActionsTailscaleSSH' -DisplayName 'Session Actions Tailnet SSH' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 -RemoteAddress '100.64.0.0/10' -InterfaceAlias $Tailnet[0].Name | Out-Null
Start-Service sshd
if (-not (Get-NetTCPConnection -State Listen -LocalPort 22 -ErrorAction SilentlyContinue)) {
    throw 'OpenSSH is not listening'
}
Write-Output 'Tailnet-restricted Windows SSH is ready'
