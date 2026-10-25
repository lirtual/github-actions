# Runs only on a disposable GitHub-hosted Windows Runner.
# A RemoteDisconnect task restores a single disconnected Runner user's RDP
# session to the console so that UU Lite can continue using the same desktop.
param(
    [switch]$Install,
    [string]$RunnerUser
)
$ErrorActionPreference = 'Stop'
$TaskName = 'SessionActionsRdpConsoleHandoff'

if ($Install) {
    if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
        throw 'RDP console handoff is limited to disposable GitHub-hosted Windows Runners'
    }
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Account = Get-LocalUser -Name ([Environment]::UserName) -ErrorAction Stop
    if ($Identity.User.Value -ne $Account.SID.Value -or -not $Account.Enabled -or
        $Account.Name -cnotmatch '^[A-Za-z0-9._-]{1,64}$') {
        throw 'Unexpected Windows Runner account for RDP console handoff'
    }
    $UserName = $env:COMPUTERNAME + '\' + $Account.Name
    $EscapedUser = [Security.SecurityElement]::Escape($UserName)
    $EscapedScript = [Security.SecurityElement]::Escape($PSCommandPath)
    $ShellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $EscapedShell = [Security.SecurityElement]::Escape($ShellPath)
    $EscapedSid = [Security.SecurityElement]::Escape($Account.SID.Value)
    # InteractiveToken avoids a stored user password and only works while the
    # same account remains logged on. The task never runs as LocalSystem.
    $Xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Return disconnected Runner RDP session to console for UU Lite</Description></RegistrationInfo>
  <Triggers>
    <SessionStateChangeTrigger>
      <Enabled>true</Enabled>
      <UserId>$EscapedUser</UserId>
      <Delay>PT3S</Delay>
      <StateChange>RemoteDisconnect</StateChange>
    </SessionStateChangeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Runner">
      <UserId>$EscapedSid</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <ExecutionTimeLimit>PT30S</ExecutionTimeLimit>
    <AllowStartOnDemand>false</AllowStartOnDemand>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Runner">
    <Exec>
      <Command>$EscapedShell</Command>
      <Arguments>-NoProfile -NonInteractive -File &quot;$EscapedScript&quot; -RunnerUser &quot;$($Account.Name)&quot;</Arguments>
    </Exec>
  </Actions>
</Task>
"@
    Register-ScheduledTask -TaskName $TaskName -Xml $Xml -Force -ErrorAction Stop | Out-Null
    $RegisteredXml = Export-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    if ($RegisteredXml -notmatch '<StateChange>RemoteDisconnect</StateChange>' -or
        $RegisteredXml -notmatch '<LogonType>InteractiveToken</LogonType>') {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        throw 'RDP console handoff task verification failed'
    }
    Write-Output 'Runner RDP disconnect-to-console handoff registered'
    return
}

if ($RunnerUser -cnotmatch '^[A-Za-z0-9._-]{1,64}$') {
    throw 'Invalid RDP console handoff account'
}
# query user reports a disconnected RDP user's session as either
# "runneradmin 2 Disc" or "runneradmin rdp-tcp#0 2 Disc".
# Never assume a fixed session ID, SESSIONNAME=Console, or a console lock state.
$Rows = @(& (Join-Path $env:SystemRoot 'System32\quser.exe') 2>$null)
if ($LASTEXITCODE -ne 0) { return }
$UserPattern = [regex]::Escape($RunnerUser)
$CandidateIds = @(
    foreach ($Row in $Rows) {
        if ($Row -match ('^\s*>?\s*' + $UserPattern +
            '\s+(?:rdp-tcp#\d+\s+)?(\d+)\s+Disc(?:\s|$)')) {
            [int]$Matches[1]
        }
    }
)
# Fail closed if multiple disconnected sessions could be selected.
if ($CandidateIds.Count -ne 1 -or $CandidateIds[0] -le 0) { return }
& (Join-Path $env:SystemRoot 'System32\tscon.exe') $CandidateIds[0] '/dest:console' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'RDP console handoff failed' }
