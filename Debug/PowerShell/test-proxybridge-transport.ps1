param(
    [string]$SourceRoot,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [switch]$Fixed,
    [string]$PythonPath,
    [string]$CorePath,
    [string]$InstalledDll
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$workspace = $repo
if (!$SourceRoot) { $SourceRoot = Join-Path $repo 'third_party\proxybridge' }
$SourceRoot = [IO.Path]::GetFullPath($SourceRoot)
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Use a fresh test output directory.' }
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
if (!$PythonPath) { $PythonPath = (Get-Command python.exe -ErrorAction Stop).Source }
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$savedPreference = $ErrorActionPreference
try {
    $ErrorActionPreference = 'Continue'
    $vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    $vsCode = $LASTEXITCODE
} finally { $ErrorActionPreference = $savedPreference }
if ($vsCode -ne 0 -or !$vs) { throw 'MSVC not found.' }
$dev = Join-Path $vs 'Common7\Tools\VsDevCmd.bat'
$sdk = Join-Path $workspace '.toolchain\windows-sdk\c'
$windivert = Join-Path $workspace 'third-party\windivert-2.2.2'
$includes = @('um','shared','ucrt','winrt') | ForEach-Object { Join-Path $sdk "Include\10.0.26100.0\$_" }
$sources = @('ProxyBridge.c','pb_util.c','pb_process.c','pb_rules.c','pb_proxy.c','pb_dns.c','pb_socks5.c','pb_http.c','pb_conntrack.c','pb_relay.c') |
    ForEach-Object { '"' + (Join-Path $SourceRoot $_) + '"' }
$flags = '/nologo /utf-8 /O2 /MT /GS /guard:cf /W3 /D_CRT_SECURE_NO_WARNINGS /D_WINSOCK_DEPRECATED_NO_WARNINGS /DPROXYBRIDGE_EXPORTS /D_WIN32_WINNT=0x0A00 /DNDEBUG'
$fixedFlag = ''
if ($Fixed) { $fixedFlag = '/DPB_TRANSPORT_FIXED' }
$link = '/link /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /guard:cf /CETCOMPAT "/LIBPATH:' + $windivert + '" WinDivert.lib ws2_32.lib iphlpapi.lib advapi32.lib'
$lines = @(
    '@echo off', 'setlocal',
    ('call "' + $dev + '" -arch=x64 -host_arch=x64 >nul'), 'if errorlevel 1 exit /b 1',
    ('set "INCLUDE=' + ($includes -join ';') + ';%INCLUDE%"'),
    ('set "LIB=' + (Join-Path $sdk 'um\x64') + ';' + (Join-Path $sdk 'ucrt\x64') + ';%LIB%"'),
    ('cl.exe ' + $flags + ' "/I' + $windivert + '" ' + ($sources -join ' ') + ' /LD ' + $link + ' /OUT:ProxyBridge.dll'),
    'if errorlevel 1 exit /b 1',
    ('cl.exe ' + $flags + ' ' + $fixedFlag + ' "/I' + $windivert + '" "/I' + $SourceRoot + '" "' +
        (Join-Path $repo 'third_party\proxybridge\tests\transport_harness.c') + '" ' + ($sources -join ' ') +
        ' /Fe:transport-harness.exe ' + $link),
    'exit /b %errorlevel%'
)
$build = Join-Path $OutputDirectory 'build.cmd'
[IO.File]::WriteAllLines($build, $lines, [Text.Encoding]::ASCII)
Copy-Item -LiteralPath (Join-Path $windivert 'WinDivert.dll') -Destination $OutputDirectory
Push-Location $OutputDirectory
try {
    $ErrorActionPreference = 'Continue'
    $buildOutput = @(& $env:ComSpec /d /c $build 2>&1)
    $buildCode = $LASTEXITCODE
    [IO.File]::WriteAllLines((Join-Path $OutputDirectory 'build.log'), [string[]]$buildOutput, [Text.UTF8Encoding]::new($false))
} finally { $ErrorActionPreference = $savedPreference; Pop-Location }
if ($buildCode -ne 0) { Get-Content (Join-Path $OutputDirectory 'build.log') -Tail 30; throw "Native build failed: $buildCode" }
$arguments = @('-B', (Join-Path $repo 'third_party\proxybridge\tests\transport_test.py'), '--harness', (Join-Path $OutputDirectory 'transport-harness.exe'), '--output', (Join-Path $OutputDirectory 'results.json'))
if ($Fixed) { $arguments += '--fixed' }
if ($InstalledDll) { $arguments += @('--installed-dll', $InstalledDll) }
try {
    $ErrorActionPreference = 'Continue'
    & $PythonPath @arguments
    $testCode = $LASTEXITCODE
} finally { $ErrorActionPreference = $savedPreference }
if ($testCode -ne 0) { throw "Targeted tests failed: $testCode" }
if ($Fixed) {
    $udpArguments = @('-B', (Join-Path $SourceRoot 'tests\udp_test.py'), '--harness',
        (Join-Path $OutputDirectory 'transport-harness.exe'), '--output', (Join-Path $OutputDirectory 'udp-results.json'))
    if ($CorePath) { $udpArguments += @('--core', ([IO.Path]::GetFullPath($CorePath))) }
    try {
        $ErrorActionPreference = 'Continue'
        & $PythonPath @udpArguments
        $udpCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $savedPreference }
    if ($udpCode -ne 0) { throw "UDP transport tests failed: $udpCode" }
    try {
        $ErrorActionPreference = 'Continue'
        & $PythonPath -B (Join-Path $SourceRoot 'tests\domain_test.py') --harness (Join-Path $OutputDirectory 'transport-harness.exe') --output (Join-Path $OutputDirectory 'domain-results.json')
        $domainCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $savedPreference }
    if ($domainCode -ne 0) { throw "DNS/domain/startup tests failed: $domainCode" }
}
Get-FileHash -LiteralPath (Join-Path $OutputDirectory 'ProxyBridge.dll') -Algorithm SHA256
