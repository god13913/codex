param([switch]$ValidateOnly,[switch]$LoadOnly)
# ASCII, Windows PowerShell 5.1; embedded in the service binary, no user scripts.
$ErrorActionPreference='Stop'
$managedName='CodexDedicatedProxy-TcpRelay-52ea90fb'
$managedGroup='CodexDedicatedProxy-ServiceRelay'

function Get-ManagedRelayRule {
    $rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {$_.Name -eq $managedName})
    if ($rules.Count -gt 1) { throw 'Ambiguous managed relay rule.' }
    if ($rules.Count -eq 1) {
        if ($rules[0].Group -ne $managedGroup) { throw 'Relay firewall name belongs to another rule.' }
        return $rules[0]
    }
}

function Test-RelayRuleEndpoint {
    param($Rule,[string]$Program,[int]$Port)
    $app=@($Rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
    $ports=@($Rule | Get-NetFirewallPortFilter -ErrorAction Stop)
    return $app.Count -eq 1 -and $ports.Count -eq 1 -and $app[0].Program -ieq $Program -and
        @($ports[0].LocalPort).Count -eq 1 -and [string]$ports[0].LocalPort -eq [string]$Port -and
        [string]$ports[0].Protocol -in @('TCP','6')
}

function Invoke-RelayFirewall {
    param([ValidateSet('Apply','Remove')][string]$Action,[string]$Program,[ValidateRange(1,65535)][int]$Port)
    $existing=Get-ManagedRelayRule
    if ($Action -eq 'Remove') {
        if ($null -eq $existing) { return }
        if (!(Test-RelayRuleEndpoint -Rule $existing -Program $Program -Port $Port)) { throw 'Relay rule changed ownership or port.' }
        Remove-NetFirewallRule -PolicyStore ActiveStore -Name $managedName -ErrorAction Stop
        if ($null -ne (Get-ManagedRelayRule)) { throw 'Relay rule removal did not complete.' }
        return
    }
    if ($null -ne $existing) {
        Remove-NetFirewallRule -PolicyStore ActiveStore -Name $managedName -ErrorAction Stop
    }
    $null=New-NetFirewallRule -PolicyStore ActiveStore -Name $managedName -Group $managedGroup -DisplayName 'Codex dedicated TCP relay' -Enabled True -Profile Any -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -Program $Program -RemoteAddress Any -EdgeTraversalPolicy Block -ErrorAction Stop
    $rule=Get-ManagedRelayRule
    if ($null -eq $rule -or !(Test-RelayRuleEndpoint -Rule $rule -Program $Program -Port $Port) -or
        [string]$rule.Enabled -ne 'True' -or [string]$rule.Direction -ne 'Inbound' -or
        [string]$rule.Action -ne 'Allow' -or [string]$rule.Profile -ne 'Any' -or
        [string]$rule.EdgeTraversalPolicy -ne 'Block') { throw 'Relay inbound rule verification failed.' }
    $addresses=@($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
    $ports=@($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
    if ($addresses.Count -ne 1 -or @($addresses[0].RemoteAddress).Count -ne 1 -or
        [string]$addresses[0].RemoteAddress -ne 'Any' -or
        @($ports[0].RemotePort).Count -ne 1 -or [string]$ports[0].RemotePort -ne 'Any') {
        throw 'Relay inbound scope verification failed.'
    }
}

if ($LoadOnly) { return }
if ($PSVersionTable.PSVersion.Major -ne 5) { throw 'Windows PowerShell 5.1 is required.' }
Import-Module (Join-Path $PSHOME 'Modules\NetSecurity\NetSecurity.psd1') -ErrorAction Stop
if ($ValidateOnly) {
    foreach ($name in @('Get-NetFirewallRule','New-NetFirewallRule','Remove-NetFirewallRule','Get-NetFirewallApplicationFilter','Get-NetFirewallPortFilter','Get-NetFirewallAddressFilter')) {
        $null=Get-Command $name -ErrorAction Stop
    }
    Write-Output 'Embedded PS5.1 firewall script validated; no rule operations.'
    return
}
try {
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { throw 'SYSTEM service required.' }
    $serviceId=[uint32]::Parse($env:CODEX_RELAY_SERVICE_PID)
    $port=[uint16]::Parse($env:CODEX_RELAY_PORT)
    $program=$env:CODEX_RELAY_PROGRAM
    $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+$serviceId) -ErrorAction Stop
    if (!$process -or $process.ExecutablePath -ine $program -or $process.Name -ine 'codex-proxy-service.exe') { throw 'Service identity mismatch.' }
    $selfProcess=Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID) -ErrorAction Stop
    if (!$selfProcess -or $selfProcess.ParentProcessId -ne $serviceId) { throw 'Firewall worker parent mismatch.' }
    if ($env:CODEX_RELAY_ACTION -eq 'Apply') {
        $listeners=@(Get-NetTCPConnection -OwningProcess $serviceId -State Listen -ErrorAction Stop | Select-Object -ExpandProperty LocalPort -Unique)
        if ($listeners.Count -ne 1 -or $listeners[0] -ne $port) { throw 'Relay socket is not ready.' }
    }
    Invoke-RelayFirewall -Action $env:CODEX_RELAY_ACTION -Program $program -Port $port
    exit 0
} catch {
    # No process environment, proxy configuration or raw error is logged.
    exit 1
}
