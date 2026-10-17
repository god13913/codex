param(
    [ValidateSet('Check', 'Test', 'KernelTest', 'RouteTest', 'Dev', 'Release')][string]$Stage = 'Release',
    [string]$CorePath = '',
    [string]$BuildProxy = '',
    [string]$RegistryBridge = '',
    [string]$TargetDirectory = '',
    [string]$OutputDirectory = '',
    [string]$RgPath = '',
    [string]$VoicePackageDirectory = '',
    # Max concurrent Cargo jobs. 0 or omitted = follow the host CPU (logical cores - 1).
    [int]$BuildJobs = 0,
    [switch]$DesktopOnly,
    [switch]$FreshBuild,
    [switch]$Offline
)
$ErrorActionPreference = 'Stop'
# No machine-specific default: every caller must pass a pinned Mihomo executable.
if ($Stage -in @('Dev', 'Release') -and -not $CorePath) { throw 'Pass -CorePath with a pinned Mihomo executable.' }

# Collapse duplicate-cased environment variables (http_proxy vs HTTP_PROXY, https_proxy vs
# HTTPS_PROXY). Windows environment names are case-insensitive; importing a batch environment
# that exports both spellings makes SetEnvironmentVariable fail with "already contains the key".
foreach ($proxyPair in @(
        @('http_proxy', 'HTTP_PROXY'),
        @('https_proxy', 'HTTPS_PROXY'),
        @('all_proxy', 'ALL_PROXY'),
        @('no_proxy', 'NO_PROXY')
    )) {
    $lower = $proxyPair[0]
    $upper = $proxyPair[1]
    $proxyValue = [Environment]::GetEnvironmentVariable($upper, 'Process')
    if ($null -eq $proxyValue) {
        $proxyValue = [Environment]::GetEnvironmentVariable($lower, 'Process')
    }
    if ($null -ne $proxyValue) {
        # Both names refer to the same Windows variable. Preserve its value before
        # removing either spelling, then restore exactly one canonical entry.
        [Environment]::SetEnvironmentVariable($lower, $null, 'Process')
        [Environment]::SetEnvironmentVariable($upper, $null, 'Process')
        [Environment]::SetEnvironmentVariable($upper, $proxyValue, 'Process')
    }
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    [IO.File]::WriteAllText($Path, $Content, [Text.UTF8Encoding]::new($false))
}

$repoRoot = Split-Path $PSScriptRoot -Parent
$workspaceRoot = Split-Path $repoRoot -Parent
$voiceEnabled = [bool]$VoicePackageDirectory
$voiceTarget = 'x86_64-pc-windows-msvc'
$voicePackageRoot = $null
$voiceSource = $null
$voiceInputManifest = $null
$rgSource = $null
if ($voiceEnabled) {
    if ($Stage -ne 'Release') {
        throw 'VoicePackageDirectory is only valid for the Release stage'
    }
    $voicePackageRoot = [IO.Path]::GetFullPath($VoicePackageDirectory)
    $voiceSource = Join-Path $voicePackageRoot 'codex-resources\voice'
    $voiceManifestPath = Join-Path $voiceSource 'manifest.json'
    if (!(Test-Path -LiteralPath $voiceSource -PathType Container)) {
        throw "Voice package is missing codex-resources\voice: $voiceSource"
    }
    if (!(Test-Path -LiteralPath $voiceManifestPath -PathType Leaf)) {
        throw "Voice package is missing its manifest: $voiceManifestPath"
    }
    $voiceInputManifest = Get-Content -LiteralPath $voiceManifestPath -Raw | ConvertFrom-Json
    $currentBuildCommit = (& git -C $repoRoot rev-parse HEAD).Trim()
    if ($voiceInputManifest.buildCommit -ne $currentBuildCommit) {
        throw "Voice package build commit mismatch: expected $currentBuildCommit, got $($voiceInputManifest.buildCommit)"
    }
    if ($voiceInputManifest.appTarget -ne $voiceTarget -or $voiceInputManifest.voiceTarget -ne $voiceTarget) {
        throw "Voice package target mismatch: expected $voiceTarget"
    }
    $requiredVoiceFiles = @(
        'bin\codex-voice-host.exe',
        'bin\gstreamer-1.0-0.dll',
        'bin\gio-2.0-0.dll',
        'bin\gstapp.dll',
        'bin\gstaudioconvert.dll',
        'bin\gstaudioresample.dll',
        'bin\gstcoreelements.dll',
        'bin\gstopus.dll',
        'bin\gstrtp.dll',
        'bin\gstrtpmanager.dll'
    )
    foreach ($relative in $requiredVoiceFiles) {
        $path = Join-Path $voiceSource $relative
        if (!(Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Voice package is missing required file: $relative"
        }
    }
    $voiceHashEntries = @($voiceInputManifest.sha256.psobject.Properties | Where-Object Name -like 'codex-resources/voice/*')
    if ($voiceHashEntries.Count -lt $requiredVoiceFiles.Count) {
        throw 'Voice package manifest does not cover the complete voice payload'
    }
    foreach ($entry in $voiceHashEntries) {
        $relative = [string]$entry.Name
        $sourcePath = Join-Path $voicePackageRoot ($relative.Replace('/', '\'))
        if (!(Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
            throw "Voice package manifest references a missing file: $relative"
        }
        $actual = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne ([string]$entry.Value).ToLowerInvariant()) {
            throw "Voice package hash mismatch: $relative"
        }
    }
}
if ($Stage -in @('Dev', 'Release')) {
    if ($RgPath) {
        $rgSource = [IO.Path]::GetFullPath($RgPath)
    } elseif ($voicePackageRoot) {
        $officialRg = Join-Path $voicePackageRoot 'codex-path\rg.exe'
        if (Test-Path -LiteralPath $officialRg -PathType Leaf) {
            $rgSource = $officialRg
        }
    }
    if (!$rgSource -or !(Test-Path -LiteralPath $rgSource -PathType Leaf)) {
        throw 'Release requires a bundled Windows ripgrep executable; pass -RgPath or provide codex-path\rg.exe in VoicePackageDirectory'
    }
    if ([IO.Path]::GetFileName($rgSource) -ine 'rg.exe') {
        throw "Bundled ripgrep must be named rg.exe: $rgSource"
    }
}
if ($TargetDirectory) {
    $env:CARGO_TARGET_DIR = [IO.Path]::GetFullPath($TargetDirectory)
} else {
    $env:CARGO_TARGET_DIR = Join-Path $repoRoot 'codex-rs\target'
}
if ($FreshBuild) {
    if (Test-Path -LiteralPath $env:CARGO_TARGET_DIR) {
        if (@(Get-ChildItem -LiteralPath $env:CARGO_TARGET_DIR -Force).Count -gt 0) {
            throw 'FreshBuild requires an empty new target directory; old caches are preserved.'
        }
    }
    $env:CARGO_INCREMENTAL = '0'
    $env:RUSTC_WRAPPER = ''
    $env:RUSTC_WORKSPACE_WRAPPER = ''
}
New-Item -ItemType Directory -Path $env:CARGO_TARGET_DIR -Force | Out-Null
$toolchainRoot = Join-Path $workspaceRoot '.toolchain'
$buildTemporaryDirectory = Join-Path $toolchainRoot 'build-tmp'
New-Item -ItemType Directory -Path $buildTemporaryDirectory -Force | Out-Null
# Native build tools such as protoc cannot consistently decode a Unicode user profile path.
$env:TEMP = $buildTemporaryDirectory
$env:TMP = $buildTemporaryDirectory
$env:RUSTUP_HOME = Join-Path $toolchainRoot 'rustup-clean'
$env:CARGO_HOME = Join-Path $toolchainRoot 'cargo'
$rustBin = Join-Path $env:RUSTUP_HOME 'toolchains\1.95.0-x86_64-pc-windows-msvc\bin'
$env:PATH = $rustBin + ';' + (Join-Path $env:CARGO_HOME 'bin') + ';' + $env:PATH
$env:RUSTC = Join-Path $rustBin 'rustc.exe'
$env:CARGO_HTTP_MULTIPLEXING = 'false'
$env:CARGO_HTTP_TIMEOUT = '120'
# Parallelism: scale with the host CPU instead of the previous hardcoded 4.
# codegen-units = 4 governs in-crate splitting; CARGO_BUILD_JOBS governs how many
# crates/codegen units Cargo runs concurrently. Pinning it to 4 throttled release
# builds to a fraction of the available cores. Default to all logical cores, leave
# one free so the desktop stays responsive, and let -BuildJobs override explicitly.
$logicalCores = [Environment]::ProcessorCount
if ($logicalCores -lt 1) { $logicalCores = 1 }
if ($BuildJobs -gt 0) {
    $env:CARGO_BUILD_JOBS = [string]$BuildJobs
} else {
    $env:CARGO_BUILD_JOBS = [string][Math]::Max(1, $logicalCores - 1)
}
$env:CARGO_NET_GIT_FETCH_WITH_CLI = 'true'
# These overrides affect only this build process and never persistent Git configuration.
$env:GIT_CONFIG_COUNT = '1'
$env:GIT_CONFIG_KEY_0 = 'url.https://github.com/.insteadOf'
$env:GIT_CONFIG_VALUE_0 = 'ssh://git@github.com/'
$gitShimDirectory = Join-Path $toolchainRoot 'git-shim'
$gitShimPath = Join-Path $gitShimDirectory 'git.exe'
$actualGit = Get-Command git.exe -All | Where-Object Source -ne $gitShimPath | Select-Object -First 1
if (!$actualGit) { throw 'A real Git installation is required' }
$env:CODEX_BUILD_REAL_GIT = $actualGit.Source
New-Item -ItemType Directory -Path $gitShimDirectory -Force | Out-Null
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $compiler /nologo /target:exe "/out:$gitShimDirectory\git.exe" (Join-Path $PSScriptRoot 'git-fetch-shim.cs')
if ($LASTEXITCODE -ne 0) { throw 'Cannot compile build-only Git fetch helper' }
$env:PATH = $gitShimDirectory + ';' + $env:PATH
if ($BuildProxy) {
    $env:CARGO_HTTP_PROXY = $BuildProxy
    $env:GIT_CONFIG_COUNT = '6'
    $env:GIT_CONFIG_KEY_1 = 'http.proxy'
    $env:GIT_CONFIG_VALUE_1 = $BuildProxy
    $env:GIT_CONFIG_KEY_2 = 'http.version'
    $env:GIT_CONFIG_VALUE_2 = 'HTTP/1.1'
    $env:GIT_CONFIG_KEY_3 = 'http.sslBackend'
    $env:GIT_CONFIG_VALUE_3 = 'schannel'
    $env:GIT_CONFIG_KEY_4 = 'http.lowSpeedLimit'
    $env:GIT_CONFIG_VALUE_4 = '1000'
    $env:GIT_CONFIG_KEY_5 = 'http.lowSpeedTime'
    $env:GIT_CONFIG_VALUE_5 = '30'
}
$lockPath = Join-Path $repoRoot 'codex-rs\Cargo.lock'
$lockText = Get-Content -LiteralPath $lockPath -Raw
if ($lockText -notmatch '(?ms)\[\[package\]\]\s*\r?\nname = "v8"\s*\r?\nversion = "([^"]+)"') {
    throw 'Cannot resolve the pinned Rusty V8 crate version from Cargo.lock'
}
$rustyV8Version = $Matches[1]
$rustyV8VersionKey = $rustyV8Version.Replace('.', '_')
$rustyV8Target = 'x86_64-pc-windows-msvc'
$rustyV8Profile = 'ptrcomp_sandbox_release'
$rustyV8BaseUrl = "https://github.com/openai/codex/releases/download/rusty-v8-v$rustyV8Version"
$rustyV8Cache = Join-Path $toolchainRoot 'rusty-v8'
New-Item -ItemType Directory -Path $rustyV8Cache -Force | Out-Null

function Save-RemoteArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$Destination,
        [string]$Proxy
    )
    $temporary = "$Destination.download"
    $request = @{
        Uri = $Uri
        OutFile = $temporary
        ErrorAction = 'Stop'
    }
    if ($Proxy) { $request.Proxy = $Proxy }
    Invoke-WebRequest @request
    Move-Item -LiteralPath $temporary -Destination $Destination -Force
}

$checksumName = "rusty_v8_${rustyV8Profile}_${rustyV8Target}.sha256"
$archiveName = "rusty_v8_${rustyV8Profile}_${rustyV8Target}.lib.gz"
$bindingName = "src_binding_${rustyV8Profile}_${rustyV8Target}.rs"
$checksumPath = Join-Path $rustyV8Cache $checksumName
$archivePath = Join-Path $rustyV8Cache $archiveName
$bindingPath = Join-Path $rustyV8Cache $bindingName
$trustedManifest = Join-Path $repoRoot "third_party\v8\rusty_v8_${rustyV8VersionKey}_release_manifests.sha256"

if (!(Test-Path -LiteralPath $checksumPath)) {
    Save-RemoteArtifact "$rustyV8BaseUrl/$checksumName" $checksumPath $BuildProxy
}
$trustedLine = Select-String -LiteralPath $trustedManifest -Pattern ([regex]::Escape("  $checksumName")) | Select-Object -First 1
if (!$trustedLine) { throw "Trusted Rusty V8 checksum manifest has no entry for $checksumName" }
$expectedManifestHash = ($trustedLine.Line -split '\s+')[0].ToLowerInvariant()
$actualManifestHash = (Get-FileHash -LiteralPath $checksumPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualManifestHash -ne $expectedManifestHash) {
    throw "Rusty V8 checksum manifest mismatch for $checksumName"
}

foreach ($artifact in @(@{ Name = $archiveName; Path = $archivePath }, @{ Name = $bindingName; Path = $bindingPath })) {
    if (!(Test-Path -LiteralPath $artifact.Path)) {
        Save-RemoteArtifact "$rustyV8BaseUrl/$($artifact.Name)" $artifact.Path $BuildProxy
    }
    $checksumLine = Select-String -LiteralPath $checksumPath -Pattern ([regex]::Escape("  $($artifact.Name)")) | Select-Object -First 1
    if (!$checksumLine) { throw "Rusty V8 checksum file has no entry for $($artifact.Name)" }
    $expectedHash = ($checksumLine.Line -split '\s+')[0].ToLowerInvariant()
    $actualHash = (Get-FileHash -LiteralPath $artifact.Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "Rusty V8 artifact checksum mismatch for $($artifact.Name)"
    }
}
$env:RUSTY_V8_ARCHIVE = $archivePath
$env:RUSTY_V8_SRC_BINDING_PATH = $bindingPath
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$installation) { throw 'Visual Studio C++ build tools are required' }
$devCommand = Join-Path $installation 'Common7\Tools\VsDevCmd.bat'
$devEnvironment = & cmd.exe /d /s /c "`"`"$devCommand`" -arch=x64 -host_arch=x64 >nul && set`""
# Windows environment variables are case-insensitive, so a batch environment that exports
# both http_proxy and HTTP_PROXY makes SetEnvironmentVariable throw "already contains the
# key". Track the keys we have applied and keep only the last occurrence of each name.
$appliedEnvKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($entry in $devEnvironment) {
    if ($entry -match '^([^=]+)=(.*)$') {
        $key = $Matches[1]
        if (!$appliedEnvKeys.Add($key)) { continue }
        [Environment]::SetEnvironmentVariable($key, $Matches[2], 'Process')
    }
}
$localSdk = Join-Path $toolchainRoot 'windows-sdk\c'
if (Test-Path -LiteralPath (Join-Path $localSdk 'um\x64\kernel32.Lib')) {
    $env:LIB = (Join-Path $localSdk 'um\x64') + ';' + (Join-Path $localSdk 'ucrt\x64') + ';' + $env:LIB
    $sdkIncludeRoot = Join-Path $localSdk 'Include\10.0.26100.0'
    $sdkIncludes = @('um', 'shared', 'ucrt', 'winrt') | ForEach-Object { Join-Path $sdkIncludeRoot $_ }
    $env:INCLUDE = ($sdkIncludes -join ';') + ';' + $env:INCLUDE
}
$manifestTool = Get-ChildItem -LiteralPath $localSdk -Recurse -File -Filter 'mt.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($manifestTool) {
    $env:PATH = $manifestTool.Directory.FullName + ';' + $env:PATH
} elseif (!(Get-Command mt.exe -ErrorAction SilentlyContinue)) {
    throw 'Windows SDK mt.exe is required to link manifest-bearing sandbox helpers'
}
$nativeOutput = Join-Path $env:CARGO_TARGET_DIR 'native-proxybridge'
if ($Stage -in @('Dev', 'Release')) {
    $nativeSource = Join-Path $repoRoot 'third_party\proxybridge'
    $windivert = Join-Path $workspaceRoot 'third-party\windivert-2.2.2'
    $nativeSources = @('ProxyBridge.c','pb_util.c','pb_process.c','pb_rules.c','pb_proxy.c','pb_dns.c','pb_socks5.c','pb_http.c','pb_conntrack.c','pb_relay.c') |
        ForEach-Object { Join-Path $nativeSource $_ }
    New-Item -ItemType Directory -Path $nativeOutput -Force | Out-Null
    Push-Location $nativeOutput
    $nativePreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & cl.exe /nologo /utf-8 /O2 /MT /GS /guard:cf /W3 /D_CRT_SECURE_NO_WARNINGS /D_WINSOCK_DEPRECATED_NO_WARNINGS /DPROXYBRIDGE_EXPORTS /DNDEBUG "/I$windivert" @nativeSources /LD /link /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /guard:cf /CETCOMPAT "/LIBPATH:$windivert" WinDivert.lib ws2_32.lib iphlpapi.lib advapi32.lib "/OUT:$nativeOutput\ProxyBridge.dll"
        if ($LASTEXITCODE -ne 0) { throw 'Dedicated native packet bridge build failed' }
    } finally { $ErrorActionPreference = $nativePreference; Pop-Location }
}
Push-Location (Join-Path $repoRoot 'codex-rs')
try {
    $cargo = Join-Path $rustBin 'cargo.exe'
    $registryArguments = @()
    if ($Offline) { $registryArguments += '--offline' }
    if ($RegistryBridge) {
        $registryArguments += @('--config', 'source.crates-io.replace-with="codex-build-cache"', '--config', "source.codex-build-cache.registry=`"$RegistryBridge`"")
        $env:CARGO_HTTP_PROXY = ''
        $env:CARGO_HTTP_TIMEOUT = '240'
    }
    $cargoPreference = $ErrorActionPreference
    try {
    $ErrorActionPreference = 'Continue'
    if ($Stage -eq 'Check') {
        & $cargo @registryArguments check -p codex-dedicated-proxy -p codex-cli --bin codex --bin codex-proxy-service
    } elseif ($Stage -eq 'Test') {
        & $cargo @registryArguments test -p codex-dedicated-proxy -p codex-http-client -p codex-websocket-client --lib
    } elseif ($Stage -eq 'RouteTest') {
        & $cargo @registryArguments test -p codex-login -p codex-exec-server --lib dedicated_proxy
    } elseif ($Stage -eq 'KernelTest') {
        if ((Get-FileHash -LiteralPath $CorePath -Algorithm SHA256).Hash -ne '3C107D54EF1B895E4980B53F517D52F3C1137101FA2637347C9CE343FC50D7B2') { throw 'Pinned Mihomo checksum mismatch' }
        $kernelTestDirectory = Join-Path $env:CARGO_TARGET_DIR 'debug\deps'
        New-Item -ItemType Directory -Path $kernelTestDirectory -Force -ErrorAction Stop | Out-Null
        Copy-Item -LiteralPath $CorePath -Destination (Join-Path $kernelTestDirectory 'codex-mihomo.exe') -ErrorAction Stop
        & $cargo @registryArguments test -p codex-dedicated-proxy --lib --features serde_json/arbitrary_precision -- --ignored
    } else {
        $releaseBinaries = @(
            'codex',
            'codex-proxy-service',
            'codex-code-mode-host',
            'codex-windows-sandbox-setup',
            'codex-windows-sandbox-service',
            'codex-command-runner'
        )
        if (!$DesktopOnly) { $releaseBinaries += @('codex-responses-api-proxy', 'codex-app-server') }
        $releaseBinaryArguments = foreach ($binary in $releaseBinaries) {
            @('--bin', $binary)
        }
        $profileArguments = @()
        if ($Stage -eq 'Release') { $profileArguments += '--release' }
        & $cargo @registryArguments build @profileArguments @releaseBinaryArguments
    }
    if ($LASTEXITCODE -ne 0) { throw "Cargo $Stage failed (exit $LASTEXITCODE)" }
    } finally { $ErrorActionPreference = $cargoPreference }
    if ($Stage -in @('Dev', 'Release')) {
        $destination = if ($OutputDirectory) { [IO.Path]::GetFullPath($OutputDirectory) } else { Join-Path $workspaceRoot 'release\CodexDedicated' }
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        if ((Get-FileHash -LiteralPath $CorePath -Algorithm SHA256).Hash -ne '3C107D54EF1B895E4980B53F517D52F3C1137101FA2637347C9CE343FC50D7B2') { throw 'Pinned Mihomo checksum mismatch' }
        $packageResources = Join-Path $destination 'codex-resources'
        $packagePath = Join-Path $destination 'codex-path'
        New-Item -ItemType Directory -Path $packageResources, $packagePath -Force | Out-Null
        foreach ($binary in $releaseBinaries) {
            if ($binary -ne 'codex-voice-host') {
                $profileDirectory = 'debug'
                if ($Stage -eq 'Release') { $profileDirectory = 'release' }
                $binarySource = Join-Path $env:CARGO_TARGET_DIR "$profileDirectory\$binary.exe"
                # Keep the root copy for the dedicated launcher and legacy helper lookup.
                Copy-Item -LiteralPath $binarySource -Destination $destination
                if ($binary -in @('codex-command-runner', 'codex-windows-sandbox-setup')) {
                    # Also provide the canonical official package location.
                    Copy-Item -LiteralPath $binarySource -Destination $packageResources
                }
            }
        }
        # Guard against a self-referential copy: the caller may pass an rg.exe that was
        # already taken from this packaging output directory. Copying a file onto itself
        # raises an IOException and aborts packaging.
        $rgDestination = Join-Path $packagePath 'rg.exe'
        $sameRg = [IO.Path]::GetFullPath($rgSource).TrimEnd('\') -eq [IO.Path]::GetFullPath($rgDestination).TrimEnd('\')
        if (!$sameRg) {
            Copy-Item -LiteralPath $rgSource -Destination $rgDestination -Force
        }
        if ($voiceEnabled) {
            $voiceDestination = Join-Path $destination 'codex-resources\voice'
            New-Item -ItemType Directory -Path $voiceDestination -Force | Out-Null
            foreach ($item in (Get-ChildItem -LiteralPath $voiceSource -Force)) {
                Copy-Item -LiteralPath $item.FullName -Destination $voiceDestination -Recurse -Force
            }
            $voiceManifestHashes = [ordered]@{}
            $voiceManifestHashes['codex.exe'] = (Get-FileHash -LiteralPath (Join-Path $destination 'codex.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
            foreach ($entry in $voiceHashEntries) {
                $relative = [string]$entry.Name
                $destinationPath = Join-Path $destination ($relative.Replace('/', '\'))
                $actual = (Get-FileHash -LiteralPath $destinationPath -Algorithm SHA256).Hash.ToLowerInvariant()
                if ($actual -ne ([string]$entry.Value).ToLowerInvariant()) {
                    throw "Copied voice payload changed: $relative"
                }
                $voiceManifestHashes[$relative] = $actual
            }
            $voiceManifest = [ordered]@{
                schemaVersion = 1
                buildCommit = $voiceInputManifest.buildCommit
                appTarget = $voiceTarget
                voiceTarget = $voiceTarget
                appVersion = '0.162.0+dedicated'
                sha256 = $voiceManifestHashes
            }
            Write-Utf8NoBom -Path (Join-Path $voiceDestination 'manifest.json') -Content ($voiceManifest | ConvertTo-Json -Depth 6)
        }
        $packageMetadata = [ordered]@{
            layoutVersion = 1
            version = '0.162.0+dedicated'
            target = $voiceTarget
            variant = 'codex'
            # The dedicated distribution keeps codex.exe at its historical root path.
            entrypoint = 'codex.exe'
            resourcesDir = 'codex-resources'
            pathDir = 'codex-path'
        }
        Write-Utf8NoBom -Path (Join-Path $destination 'codex-package.json') -Content ($packageMetadata | ConvertTo-Json -Depth 4)
        Copy-Item -LiteralPath $CorePath -Destination (Join-Path $destination 'codex-mihomo.exe')
        Copy-Item -LiteralPath (Join-Path $nativeOutput 'ProxyBridge.dll') -Destination $destination
        $windivert = Join-Path $workspaceRoot 'third-party\windivert-2.2.2'
        $expectedNative = @{
            'WinDivert.dll'='C1E060EE19444A259B2162F8AF0F3FE8C4428A1C6F694DCE20DE194AC8D7D9A2'
            'WinDivert64.sys'='8DA085332782708D8767BCACE5327A6EC7283C17CFB85E40B03CD2323A90DDC2'
        }
        foreach ($asset in $expectedNative.Keys) {
            $path = Join-Path $windivert $asset
            if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $expectedNative[$asset]) { throw "Pinned WinDivert checksum mismatch: $asset" }
            Copy-Item -LiteralPath $path -Destination $destination
        }
        if ((Get-AuthenticodeSignature -LiteralPath (Join-Path $windivert 'WinDivert64.sys')).Status -ne 'Valid') {
            throw 'WinDivert driver signature validation failed'
        }
        Copy-Item -LiteralPath (Join-Path $windivert 'WinDivert-LGPL.txt'), (Join-Path $windivert 'WinDivert-v2.2.2-source.zip') -Destination $destination
        Copy-Item -LiteralPath (Join-Path $repoRoot 'third_party\proxybridge\LICENSE') -Destination (Join-Path $destination 'LICENSE-ProxyBridge.txt')
        $bridgeSources = @((Get-ChildItem -LiteralPath (Join-Path $repoRoot 'third_party\proxybridge') -File).FullName)
        $bridgeSources += Join-Path $repoRoot 'third_party\proxybridge\tests'
        Compress-Archive -LiteralPath $bridgeSources -DestinationPath (Join-Path $destination 'ProxyBridge-source.zip') -Force
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'configure-desktop-forwarding.ps1') -Destination $destination
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'manage-desktop-proxy-service.ps1') -Destination $destination
        & (Join-Path $PSScriptRoot 'configure-desktop-forwarding.ps1') -DistributionDirectory $destination
        if (!$?) { throw 'Desktop forwarding configuration failed' }
        Copy-Item -LiteralPath (Join-Path $repoRoot 'LICENSE') -Destination (Join-Path $destination 'LICENSE-Codex.txt')
        Copy-Item -LiteralPath (Join-Path $repoRoot 'NOTICE') -Destination (Join-Path $destination 'NOTICE-Codex.txt')
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'start-dedicated-codex.cmd') -Destination (Join-Path $destination '启动Codex.cmd')
        Copy-Item -LiteralPath (Join-Path $repoRoot 'docs\dedicated-proxy.md') -Destination (Join-Path $destination '使用说明.md')
        $mihomoSources = Join-Path $workspaceRoot 'third-party\mihomo-1.19.32'
        foreach ($material in @('LICENSE-Mihomo.txt', 'mihomo-v1.19.32-source.zip')) {
            $materialPath = Join-Path $mihomoSources $material
            if (!(Test-Path -LiteralPath $materialPath)) { throw "Missing Mihomo distribution material: $material" }
            Copy-Item -LiteralPath $materialPath -Destination $destination
        }
        $distributionLabel = if ($voiceEnabled) { 'Codex 0.162.0 + Mihomo 1.19.32 + official voice runtime' } else { 'Codex 0.162.0 + Mihomo 1.19.32' }
        Write-Utf8NoBom -Path (Join-Path $destination 'codex-dedicated-proxy.distribution') -Content $distributionLabel
        $buildResultJson = @{ success=$true; stage=$Stage; targetDirectory=$env:CARGO_TARGET_DIR; outputDirectory=$destination;
           freshBuild=[bool]$FreshBuild; voiceEnabled=$voiceEnabled; testsRun=$false; completedAt=[DateTimeOffset]::Now.ToString('o') } |
           ConvertTo-Json
        Write-Utf8NoBom -Path (Join-Path $destination 'build-result.json') -Content $buildResultJson
        $checksumLines = @(Get-ChildItem -LiteralPath $destination -File -Recurse | Where-Object FullName -ne (Join-Path $destination 'SHA256SUMS.txt') | ForEach-Object {
            # [IO.Path]::GetRelativePath requires .NET Core / PS7; this script is launched
            # by Windows PowerShell 5.1, so compute the relative path manually.
            $relative = $_.FullName.Substring($destination.Length).TrimStart('\').Replace('\', '/')
            '{0}  {1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash, $relative
        })
        Write-Utf8NoBom -Path (Join-Path $destination 'SHA256SUMS.txt') -Content ($checksumLines -join [Environment]::NewLine)
        Write-Output "Custom distribution: $destination"
    }
} finally { Pop-Location }
