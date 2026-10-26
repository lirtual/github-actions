# Enable native Windows RDP on the existing Runner administrator, via Tailscale only.
# SSH and RDP authenticate the same Windows local account and SESSION_SYSTEM_PASSWORD.
$ErrorActionPreference = 'Stop'
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
# No service or system lock-policy change: one user-scoped RemoteDisconnect task.
# Registration is limited to the existing disposable GitHub-hosted Runner.
& (Join-Path $PSScriptRoot 'windows-rdp-handoff.ps1') -Install
Write-Output 'Tailscale-restricted Windows RDP is ready'
