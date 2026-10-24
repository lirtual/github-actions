# Enable native Windows RDP on the existing Runner administrator, via Tailscale only.
# Windows has one password per local account: SSH and RDP secrets must match.
$ErrorActionPreference = 'Stop'
$RdpPassword = $env:SESSION_RDP_PASSWORD
$SshPassword = $env:SESSION_SSH_PASSWORD
if ([string]::IsNullOrEmpty($RdpPassword) -or $RdpPassword.Contains([char]10) -or
    $RdpPassword.Contains([char]13) -or $RdpPassword -cne $SshPassword) {
    throw 'SESSION_RDP_PASSWORD must match SESSION_SSH_PASSWORD for the same Windows local account'
}
Remove-Variable RdpPassword, SshPassword
$env:SESSION_RDP_PASSWORD = $null
$env:SESSION_SSH_PASSWORD = $null
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Account = Get-LocalUser -Name ([Environment]::UserName) -ErrorAction Stop
if ($Account.SID.Value -ne $Identity.User.Value -or -not $Account.Enabled) {
    throw 'Expected the current enabled Windows Runner account'
}
$Tailnet = @(Get-NetAdapter | Where-Object {
    $_.InterfaceDescription -match 'Tailscale' -and $_.Status -eq 'Up'
})
if ($Tailnet.Count -ne 1) { throw 'Expected one active Tailscale adapter' }
$Addresses = @(Get-NetIPAddress -InterfaceIndex $Tailnet[0].ifIndex -AddressFamily IPv4 |
    Where-Object {
        $Parts = $_.IPAddress.Split('.')
        $Parts.Count -eq 4 -and $Parts[0] -eq '100' -and
        [int]$Parts[1] -ge 64 -and [int]$Parts[1] -le 127
    })
if ($Addresses.Count -ne 1) { throw 'Expected one Tailnet IPv4 address' }
$TailnetAddress = $Addresses[0].IPAddress

# Deny the image's permissive stock RDP firewall rules before allowing only Tailnet.
Get-NetFirewallRule -Name 'RemoteDesktop-UserMode-In-TCP','RemoteDesktop-UserMode-In-UDP' -ErrorAction SilentlyContinue |
    Disable-NetFirewallRule
Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue |
    Disable-NetFirewallRule
New-NetFirewallRule -Name 'SessionActionsTailscaleRDP' -DisplayName 'Session Actions Tailnet RDP' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389 -LocalAddress $TailnetAddress -RemoteAddress '100.64.0.0/10' -InterfaceAlias $Tailnet[0].Name | Out-Null

$Server = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
$Rdp = Join-Path $Server 'WinStations\RDP-Tcp'
Set-ItemProperty -Path $Server -Name fDenyTSConnections -Value 0
Set-ItemProperty -Path $Rdp -Name UserAuthentication -Value 1
Start-Service TermService -ErrorAction Stop
if ((Get-Service TermService -ErrorAction Stop).Status -ne 'Running' -or
    -not (Get-NetTCPConnection -State Listen -LocalPort 3389 -ErrorAction SilentlyContinue)) {
    throw 'RDP did not become ready on the Windows Runner'
}
$Rule = Get-NetFirewallRule -Name 'SessionActionsTailscaleRDP' -ErrorAction Stop
$AddressFilter = $Rule | Get-NetFirewallAddressFilter
if ($Rule.Enabled -ne 'True' -or $TailnetAddress -notin @($AddressFilter.LocalAddress)) {
    throw 'RDP firewall is not restricted to the Tailnet address'
}
Write-Output 'Tailscale-restricted Windows RDP is ready'
