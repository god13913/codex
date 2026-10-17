param(
    [ValidateSet('Install','Prepare','Uninstall','Status')][string]$Action = 'Status',
    [string]$RuntimeDirectory = $PSScriptRoot,
    [string]$ConfigHome = '',
    [string]$InstallDirectory = ''
)
# Windows PowerShell 5.1/.NET Framework compatible. No passwords in arguments.
$ErrorActionPreference = 'Stop'
$serviceName = 'CodexDedicatedProxy'
if (!$InstallDirectory) { $InstallDirectory = Join-Path $env:ProgramFiles 'CodexDedicatedProxy' }
$installRoot = [IO.Path]::GetFullPath($InstallDirectory).TrimEnd('\')
$programRoot = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\')
if (!$installRoot.StartsWith($programRoot + '\',[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Privileged service code must be installed below Program Files.'
}
for ($cursor = $installRoot; $cursor -and $cursor.Length -ge $programRoot.Length; $cursor = [IO.Path]::GetDirectoryName($cursor)) {
    if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Service directory links are not allowed.' }
}
$assets = Join-Path $installRoot 'runtime'
$cli = Join-Path $assets 'codex.exe'
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($Action -eq 'Status') {
    if ($service) { $service | Select-Object Name,Status,StartType } else { Write-Output 'Service is not installed.' }
    $ready = Join-Path $installRoot 'ready.json'
    if (Test-Path -LiteralPath $ready) { Get-Content -LiteralPath $ready -Raw }
    return
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script once as administrator. The desktop itself must remain unelevated.'
}
if ($Action -eq 'Uninstall') {
    if ($service) {
        Stop-Service -Name $serviceName -ErrorAction Stop
        $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(30))
        $saved = $ErrorActionPreference
        try { $ErrorActionPreference = 'Continue'; & sc.exe delete $serviceName; $code = $LASTEXITCODE }
        finally { $ErrorActionPreference = $saved }
        if ($code -ne 0) { throw "Service deletion failed: $code" }
    }
    [Environment]::SetEnvironmentVariable('CODEX_CLI_PATH',$null,'User')
    [Environment]::SetEnvironmentVariable('CODEX_CLI_PATH',$null,'Process')
    Write-Output 'Service removed. Files and old runtimes are retained. Completely reopen the desktop to use its bundled CLI.'
} else {
    if ($service -and $Action -ne 'Prepare') { throw 'Service already exists. Stop and uninstall it before testing another candidate; its files will be retained.' }
    if (Test-Path -LiteralPath $installRoot) { throw 'Install directory already exists; choose a new empty directory to preserve it.' }
    if (Get-Process -Name ChatGPT -ErrorAction SilentlyContinue) { throw 'Completely exit the desktop before installing the service; its kernel may own the proxy port.' }
    if (!$ConfigHome) {
        $ConfigHome = $env:CODEX_HOME
        if (!$ConfigHome) { $ConfigHome = Join-Path $env:USERPROFILE '.codex' }
    }
    $runtimeRoot = [IO.Path]::GetFullPath($RuntimeDirectory).TrimEnd('\')
    foreach ($name in @('codex.exe','codex-proxy-service.exe','codex-mihomo.exe','ProxyBridge.dll','WinDivert.dll','WinDivert64.sys','desktop-forwarding.json')) {
        if (!(Test-Path -LiteralPath (Join-Path $runtimeRoot $name) -PathType Leaf)) { throw "Missing runtime file: $name" }
    }
    # Restrict the parent before copying privileged executable code or credentials.
    New-Item -ItemType Directory -Path $installRoot | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $account = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($account,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    $ownerRule = New-Object Security.AccessControl.FileSystemAccessRule($identity.User,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($ownerRule)
    Set-Acl -LiteralPath $installRoot -AclObject $acl
    New-Item -ItemType Directory -Path $assets | Out-Null
    foreach ($file in Get-ChildItem -LiteralPath $runtimeRoot -File -Recurse) {
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Runtime links are not allowed.' }
        $relative = $file.FullName.Substring($runtimeRoot.Length).TrimStart('\')
        $destination = Join-Path $assets $relative
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $destination
    }
    $serviceHome = Join-Path $installRoot 'home'
    New-Item -ItemType Directory -Path (Join-Path $serviceHome 'dedicated-proxy') -Force | Out-Null
    $privateAcl = New-Object Security.AccessControl.DirectorySecurity
    $privateAcl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $account = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($account,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $privateAcl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $serviceHome -AclObject $privateAcl
    Set-Acl -LiteralPath (Join-Path $serviceHome 'dedicated-proxy') -AclObject $privateAcl
    $previousHome = $env:CODEX_HOME
    $saved = $ErrorActionPreference
    try {
        $env:CODEX_HOME = [IO.Path]::GetFullPath($ConfigHome)
        $ErrorActionPreference = 'Continue'
        $output = @(& $cli proxy service-prepare 2>&1)
        $code = $LASTEXITCODE
    } finally { $env:CODEX_HOME = $previousHome; $ErrorActionPreference = $saved }
    if ($code -ne 0 -or (($output -join "`n") -notmatch '"service_prepared":true')) {
        throw 'Protected service configuration could not be prepared. No service was registered.'
    }
    # Stage an upgrade in a fresh protected directory. The caller owns the SCM
    # transaction/rollback; staging never changes the running service or CLI selection.
    if ($Action -eq 'Prepare') {
        Write-Output 'Protected service runtime prepared. Service and CLI selection were not changed.'
        return
    }
    $serviceExe = Join-Path $assets 'codex-proxy-service.exe'
    New-Service -Name $serviceName -BinaryPathName ('"' + $serviceExe + '"') -DisplayName 'Codex dedicated proxy' -StartupType Automatic -Description 'Prepares dedicated GPT/Codex forwarding before desktop startup. Does not change system proxy or system DNS.' | Out-Null
    $saved = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/15000/restart/30000
        if ($LASTEXITCODE -ne 0) { throw 'Cannot configure service recovery.' }
        & sc.exe failureflag $serviceName 1
        if ($LASTEXITCODE -ne 0) { throw 'Cannot configure service failure recovery.' }
    } finally { $ErrorActionPreference = $saved }
    Start-Service -Name $serviceName
    $service = Get-Service -Name $serviceName
    $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(60))
    $ready = Get-Content -LiteralPath (Join-Path $installRoot 'ready.json') -Raw | ConvertFrom-Json
    if (!$ready.forwarding_ready -or !$ready.firewall_ready -or [int]$ready.relay_port -le 0 -or
        $ready.owner_sid -ne $identity.User.Value) { throw 'Service has not confirmed forwarding and relay firewall readiness.' }
    # Match the user CLI credentials to the service snapshot. Settings are unchanged.
    [Environment]::SetEnvironmentVariable('CODEX_CLI_PATH',$cli,'User')
    [Environment]::SetEnvironmentVariable('CODEX_CLI_PATH',$cli,'Process')
    Write-Output 'Service is ready. Open the desktop normally. Old runtimes were retained.'
}
if (!('CodexProxy.EnvironmentBroadcast' -as [type])) {
    Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; namespace CodexProxy { public static class EnvironmentBroadcast { [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr SendMessageTimeout(IntPtr h, uint m, UIntPtr w, string l, uint f, uint t, out UIntPtr r); } }'
}
$result = [UIntPtr]::Zero
[void][CodexProxy.EnvironmentBroadcast]::SendMessageTimeout([IntPtr]0xffff,0x1a,[UIntPtr]::Zero,'Environment',2,5000,[ref]$result)
