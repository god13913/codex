# Windows PowerShell 5.1. Mock-only rule lifecycle tests; never imports NetSecurity.
$ErrorActionPreference='Stop'
$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repoRoot 'codex-rs\dedicated-proxy\src\desktop\relay_firewall.ps1') -LoadOnly
$script:fakeRules=@{}
$script:wrongProgram=$false
$script:createFails=$false
$script:passed=0
function Assert-Test([bool]$Value,[string]$Label) {
    if (!$Value) { throw ('FAIL: '+$Label) }
    $script:passed++
}
function Assert-Throws([scriptblock]$Action,[string]$Label) {
    $threw=$false
    try { & $Action } catch { $threw=$true }
    Assert-Test $threw $Label
}
function Get-NetFirewallRule {
    [CmdletBinding()]param([string]$PolicyStore)
    if ($PolicyStore -ne 'ActiveStore') { throw 'Wrong store.' }
    foreach ($value in $script:fakeRules.Values) { $value }
}
function Remove-NetFirewallRule {
    [CmdletBinding()]param([string]$PolicyStore,[string]$Name)
    if ($PolicyStore -ne 'ActiveStore' -or $Name -ne $managedName) { throw 'Unexpected removal.' }
    $script:fakeRules.Remove($Name)
}
function New-NetFirewallRule {
    [CmdletBinding()]param([string]$PolicyStore,[string]$Name,[string]$Group,[string]$DisplayName,[string]$Enabled,[string]$Profile,[string]$Direction,[string]$Action,[string]$Protocol,[int]$LocalPort,[string]$Program,[string]$RemoteAddress,[string]$EdgeTraversalPolicy)
    if ($script:createFails) { throw 'Simulated firewall failure.' }
    if ($PolicyStore -ne 'ActiveStore') { throw 'Wrong store.' }
    $script:fakeRules[$Name]=[pscustomobject]@{Name=$Name;Group=$Group;Enabled=$Enabled;Profile=$Profile;Direction=$Direction;Action=$Action;Protocol=$Protocol;LocalPort=[string]$LocalPort;Program=$Program;RemoteAddress=$RemoteAddress;RemotePort='Any';EdgeTraversalPolicy=$EdgeTraversalPolicy}
}
function Get-NetFirewallApplicationFilter {
    [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$Rule)
    process {
        $program=$Rule.Program
        if ($script:wrongProgram) { $program='C:\other.exe' }
        [pscustomobject]@{Program=$program}
    }
}
function Get-NetFirewallPortFilter {
    [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$Rule)
    process { [pscustomobject]@{Protocol=$Rule.Protocol;LocalPort=$Rule.LocalPort;RemotePort=$Rule.RemotePort} }
}
function Get-NetFirewallAddressFilter {
    [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$Rule)
    process { [pscustomobject]@{RemoteAddress=$Rule.RemoteAddress} }
}
$program='C:\Program Files\CodexDedicatedProxy-test\runtime\codex-proxy-service.exe'
$script:fakeRules['unrelated']=[pscustomobject]@{Name='unrelated';Group='other'}
Invoke-RelayFirewall -Action Apply -Program $program -Port 55584
Assert-Test ($script:fakeRules.Count -eq 2) 'apply preserves other rules'
Assert-Test ($script:fakeRules[$managedName].Program -eq $program -and $script:fakeRules[$managedName].LocalPort -eq '55584') 'exact program and current port'
Assert-Test ($script:fakeRules[$managedName].Protocol -eq 'TCP' -and $script:fakeRules[$managedName].Direction -eq 'Inbound') 'inbound TCP only'
Invoke-RelayFirewall -Action Apply -Program $program -Port 56610
Assert-Test ($script:fakeRules.Count -eq 2 -and $script:fakeRules[$managedName].LocalPort -eq '56610') 'restart replaces old port'
Assert-Throws { Invoke-RelayFirewall -Action Remove -Program $program -Port 55584 } 'old guard cannot delete newer port'
Assert-Test ($script:fakeRules.ContainsKey($managedName)) 'changed rule retained'
Invoke-RelayFirewall -Action Remove -Program $program -Port 56610
Assert-Test ($script:fakeRules.Count -eq 1 -and $script:fakeRules.ContainsKey('unrelated')) 'stop removes only own rule'
Invoke-RelayFirewall -Action Remove -Program $program -Port 56610
Assert-Test ($script:fakeRules.Count -eq 1) 'repeat cleanup is harmless'
$script:wrongProgram=$true
Assert-Throws { Invoke-RelayFirewall -Action Apply -Program $program -Port 55584 } 'incorrect readback refuses readiness'
$script:wrongProgram=$false
Invoke-RelayFirewall -Action Remove -Program $program -Port 55584
$script:createFails=$true
Assert-Throws { Invoke-RelayFirewall -Action Apply -Program $program -Port 55584 } 'creation failure is propagated'
Assert-Test (!$script:fakeRules.ContainsKey($managedName)) 'failed create is not a ready rule'
$script:createFails=$false
$script:fakeRules[$managedName]=[pscustomobject]@{Name=$managedName;Group='another-application'}
Assert-Throws { Invoke-RelayFirewall -Action Apply -Program $program -Port 55584 } 'foreign name collision preserved'
Assert-Test ($script:fakeRules[$managedName].Group -eq 'another-application') 'foreign rule untouched'
Write-Output ('Mock-only firewall lifecycle tests passed: '+$script:passed)
