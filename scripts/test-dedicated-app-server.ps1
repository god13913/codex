param([string]$CodexPath = '')
$ErrorActionPreference = 'Stop'
$workspaceRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (!$CodexPath) { $CodexPath = Join-Path $workspaceRoot 'release\CodexDedicated\codex.exe' }
$CodexPath = (Resolve-Path -LiteralPath $CodexPath).Path
$testHome = Join-Path $workspaceRoot ('runtime\app-server-smoke-' + [Guid]::NewGuid().ToString('N'))
$state = Join-Path $testHome 'dedicated-proxy'
New-Item -ItemType Directory -Path $state -Force | Out-Null
@{
    subscription = 'https://example.invalid/subscription'
    node = @{
        name='CODEX'; type='vless'; network='tcp'; server='example.invalid'; port=443
        uuid='00000000-0000-0000-0000-000000000001'; tls=$true; servername='example.invalid'
        'reality-opts'=@{'public-key'='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; 'short-id'=''}
    }
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $state 'subscription.json')
@{enabled=$true; mode='subscription'; updated_at=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); last_error=$null} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $state 'settings.json')
$start = [Diagnostics.ProcessStartInfo]::new($CodexPath, 'app-server --listen stdio://')
$start.UseShellExecute=$false; $start.CreateNoWindow=$true
$start.RedirectStandardInput=$true; $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
$start.Environment['CODEX_HOME']=$testHome
$start.Environment.Remove('OPENAI_API_KEY') | Out-Null
$start.Environment.Remove('CODEX_API_KEY') | Out-Null
$backend = [Diagnostics.Process]::Start($start)
$kernelPid = $null
try {
    $stderr = $backend.StandardError.ReadToEndAsync()
    $initialize = @{id=1; method='initialize'; params=@{clientInfo=@{name='dedicated-proxy-smoke'; version='1.0.0'}; capabilities=@{explicitGatewayOauth=$true}}}
    $backend.StandardInput.WriteLine(($initialize | ConvertTo-Json -Depth 5 -Compress))
    $backend.StandardInput.Flush()
    $deadline=[DateTime]::UtcNow.AddSeconds(30)
    $initialized=$false
    while ([DateTime]::UtcNow -lt $deadline) {
        $line=$backend.StandardOutput.ReadLineAsync()
        if (!$line.Wait(10000) -or $null -eq $line.Result) { throw 'App-server initialization timeout' }
        $reply=$line.Result | ConvertFrom-Json
        if ($reply.id -eq 1) {
            if ($reply.PSObject.Properties.Name -contains 'error') { throw 'App-server rejected initialization' }
            $initialized=$true; break
        }
    }
    if (!$initialized) { throw 'App-server did not initialize' }
    $kernels=@(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($backend.Id)" | Where-Object Name -eq 'codex-mihomo.exe')
    if ($kernels.Count -ne 1) { throw 'App-server must own exactly one kernel' }
    $kernelPid=$kernels[0].ProcessId
    $expectedCore=Join-Path (Split-Path $CodexPath -Parent) 'codex-mihomo.exe'
    if ((Get-Process -Id $kernelPid).Path -ne $expectedCore) { throw 'Unexpected kernel path' }
    $listeners=@(Get-NetTCPConnection -State Listen -OwningProcess $kernelPid)
    if ($listeners.Count -ne 2 -or @($listeners | Where-Object LocalAddress -ne '127.0.0.1').Count) { throw 'Unexpected kernel listeners' }
    $backend.StandardInput.WriteLine('{"method":"initialized"}')
    $backend.StandardInput.Flush()
    $backend.StandardInput.Close()
    if (!$backend.WaitForExit(15000) -or $backend.ExitCode -ne 0) { throw 'App-server failed normal shutdown' }
    $deadline=[DateTime]::UtcNow.AddSeconds(5)
    while ((Get-Process -Id $kernelPid -ErrorAction SilentlyContinue) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 100 }
    if (Get-Process -Id $kernelPid -ErrorAction SilentlyContinue) { throw 'Kernel survived app-server exit' }
    foreach ($port in $listeners.LocalPort) {
        $socket=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,[int]$port)
        try { $socket.Start() } finally { $socket.Stop() }
    }
    $report=@{backend_initialized=$true; one_owned_kernel=$true; loopback_listeners_only=$true; normal_shutdown=$true; kernel_reaped=$true; own_listeners_released=$true; model_call_verified=$false}
    $report | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $testHome 'verification.json')
    $report | ConvertTo-Json -Compress
} finally {
    if (!$backend.HasExited) { $backend.Kill(); $backend.WaitForExit() }
    $backend.Dispose()
}
