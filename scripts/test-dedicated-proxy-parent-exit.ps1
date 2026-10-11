param([string]$AdminPath = '')
$ErrorActionPreference = 'Stop'
$workspaceRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (!$AdminPath) { $AdminPath = Join-Path $workspaceRoot '.toolchain\proxy-check\target\debug\codex-proxy-admin.exe' }
$AdminPath = (Resolve-Path -LiteralPath $AdminPath).Path
$testHome = Join-Path $workspaceRoot ('runtime\parent-exit-' + [Guid]::NewGuid().ToString('N'))
$state = Join-Path $testHome 'dedicated-proxy'
New-Item -ItemType Directory -Path $state -Force | Out-Null
$fixture = @{
    subscription = 'https://example.invalid/subscription'
    node = @{
        name='CODEX'; type='vless'; network='tcp'; server='example.invalid'; port=443
        uuid='00000000-0000-0000-0000-000000000001'; tls=$true; servername='example.invalid'
        'reality-opts'=@{'public-key'='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; 'short-id'=''}
    }
}
$fixture | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $state 'subscription.json')
@{enabled=$true; mode='subscription'; updated_at=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); last_error=$null} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $state 'settings.json')
$start = [Diagnostics.ProcessStartInfo]::new($AdminPath, 'hold')
$start.UseShellExecute=$false; $start.CreateNoWindow=$true
$start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
$start.Environment['CODEX_HOME']=$testHome
$parent = [Diagnostics.Process]::Start($start)
try {
    $line=$parent.StandardOutput.ReadLineAsync()
    if (!$line.Wait(15000)) { throw 'Kernel readiness timeout' }
    if (!$line.Result) { throw 'Kernel exited before readiness; use the hold command for redacted startup diagnostics' }
    $metadata=$line.Result | ConvertFrom-Json
    if (!$metadata.kernel_ready) { throw 'Kernel did not report readiness' }
    $coreProcess=Get-Process -Id $metadata.kernel_pid -ErrorAction Stop
    if ($coreProcess.Path -ne (Join-Path (Split-Path $AdminPath -Parent) 'codex-mihomo.exe')) { throw 'Unexpected kernel process' }
    $listeners=@(Get-NetTCPConnection -State Listen -OwningProcess $metadata.kernel_pid)
    if ($listeners.Count -ne 2 -or @($listeners | Where-Object LocalAddress -ne '127.0.0.1').Count -ne 0) { throw 'Unexpected kernel listeners' }
    # Simulate an abrupt parent termination. The kernel must exit through its Windows Job Object.
    $parent.Kill(); $parent.WaitForExit()
    $deadline=[DateTime]::UtcNow.AddSeconds(10)
    while ((Get-Process -Id $metadata.kernel_pid -ErrorAction SilentlyContinue) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 100 }
    if (Get-Process -Id $metadata.kernel_pid -ErrorAction SilentlyContinue) { throw 'Kernel survived parent exit' }
    foreach ($port in @($metadata.proxy_port,$metadata.control_port)) {
        $socket=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,[int]$port)
        try { $socket.Start() } finally { $socket.Stop() }
    }
    $report=@{parent_abnormal_exit=$true; kernel_reaped=$true; own_listeners_released=$true; loopback_listeners_only=$true; model_call_verified=$false}
    $report | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $testHome 'verification.json')
    $report | ConvertTo-Json -Compress
} finally {
    if (!$parent.HasExited) { $parent.Kill(); $parent.WaitForExit() }
    $parent.Dispose()
}
