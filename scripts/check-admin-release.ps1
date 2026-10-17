param(
    [string]$DistributionDirectory = '',
    [string]$TargetDirectory = ''
)
$ErrorActionPreference = 'Stop'
if (-not $DistributionDirectory -or -not $TargetDirectory) { throw 'Pass -DistributionDirectory and -TargetDirectory.' }
$distribution = [IO.Path]::GetFullPath($DistributionDirectory)
$target = [IO.Path]::GetFullPath($TargetDirectory)

function Assert-Check([bool]$Condition, [string]$Message) {
    if (!$Condition) { throw $Message }
}

# Inspect the PE file as data. Never execute a binary or load a driver here.
function Get-PeInformation([string]$Path, [bool]$ReadExports = $false) {
    $stream = [IO.File]::OpenRead($Path)
    $reader = [IO.BinaryReader]::new($stream)
    try {
        Assert-Check ($reader.ReadUInt16() -eq 0x5A4D) "Invalid DOS header: $Path"
        $stream.Position = 0x3C
        $pe = $reader.ReadUInt32()
        $stream.Position = $pe
        Assert-Check ($reader.ReadUInt32() -eq 0x4550) "Invalid PE signature: $Path"
        $machine = $reader.ReadUInt16()
        $sectionCount = $reader.ReadUInt16()
        $stream.Position = $pe + 20
        $optionalSize = $reader.ReadUInt16()
        $optional = $pe + 24
        $stream.Position = $optional
        Assert-Check ($reader.ReadUInt16() -eq 0x20B) "Expected PE32+ file: $Path"
        $names = @()
        if ($ReadExports) {
            $stream.Position = $optional + 112
            $exportRva = $reader.ReadUInt32()
            Assert-Check ($exportRva -ne 0) 'Native forwarding library has no export directory'
            $sections = @()
            for ($i = 0; $i -lt $sectionCount; $i++) {
                $stream.Position = $optional + $optionalSize + $i * 40 + 8
                $virtualSize = $reader.ReadUInt32()
                $virtualAddress = $reader.ReadUInt32()
                $rawSize = $reader.ReadUInt32()
                $rawPointer = $reader.ReadUInt32()
                $sections += @{ Start=$virtualAddress; Length=[Math]::Max($virtualSize,$rawSize); Raw=$rawPointer }
            }
            function Convert-Rva([uint32]$Rva) {
                foreach ($section in $sections) {
                    if ($Rva -ge $section.Start -and $Rva -lt ($section.Start + $section.Length)) {
                        return [long]($section.Raw + $Rva - $section.Start)
                    }
                }
                throw 'Native export address lies outside PE sections'
            }
            $stream.Position = (Convert-Rva $exportRva) + 24
            $nameCount = $reader.ReadUInt32()
            $stream.Position += 4
            $nameTable = $reader.ReadUInt32()
            Assert-Check ($nameCount -le 4096) 'Native export table exceeds size limit'
            for ($i = 0; $i -lt $nameCount; $i++) {
                $stream.Position = (Convert-Rva $nameTable) + $i * 4
                $nameRva = $reader.ReadUInt32()
                $stream.Position = Convert-Rva $nameRva
                $bytes = [Collections.Generic.List[byte]]::new()
                while (($next = $reader.ReadByte()) -ne 0) {
                    Assert-Check ($bytes.Count -lt 512) 'Native export name exceeds size limit'
                    $bytes.Add($next)
                }
                $names += [Text.Encoding]::ASCII.GetString($bytes.ToArray())
            }
        }
        return @{ Machine=$machine; Exports=$names }
    } finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

$binaries = @('codex','codex-code-mode-host','codex-responses-api-proxy',
    'codex-windows-sandbox-setup','codex-windows-sandbox-service',
    'codex-command-runner','codex-app-server')
$required = @('build-result.json','desktop-forwarding.json','ProxyBridge.dll','WinDivert.dll',
    'WinDivert64.sys','codex-mihomo.exe','LICENSE-Codex.txt','NOTICE-Codex.txt',
    'LICENSE-Mihomo.txt','mihomo-v1.19.32-source.zip','LICENSE-ProxyBridge.txt',
    'WinDivert-LGPL.txt','WinDivert-v2.2.2-source.zip','configure-desktop-forwarding.ps1',
    '使用说明.md','SHA256SUMS.txt') + ($binaries | ForEach-Object { "$_.exe" })
foreach ($name in $required) {
    $path = Join-Path $distribution $name
    Assert-Check ((Test-Path -LiteralPath $path -PathType Leaf) -and (Get-Item -LiteralPath $path).Length -gt 0) "Missing release artifact: $name"
}
$result = Get-Content -LiteralPath (Join-Path $distribution 'build-result.json') -Raw | ConvertFrom-Json
Assert-Check ($result.success -eq $true -and $result.stage -eq 'Release') 'Release build was not successful'
Assert-Check ($result.testsRun -eq $false) 'Unexpected test execution in build result'
Assert-Check ($result.freshBuild -eq $true) 'Build was not recorded as a fresh build'
Assert-Check ([IO.Path]::GetFullPath($result.targetDirectory) -eq $target) 'Fresh target directory does not match'
Assert-Check ([IO.Path]::GetFullPath($result.outputDirectory) -eq $distribution) 'Release output directory does not match'
foreach ($binary in $binaries) {
    $packaged = Join-Path $distribution "$binary.exe"
    $compiled = Join-Path $target "release\$binary.exe"
    Assert-Check ((Get-FileHash -LiteralPath $packaged).Hash -eq (Get-FileHash -LiteralPath $compiled).Hash) "Compiled artifact mismatch: $binary"
    Assert-Check ((Get-PeInformation $packaged).Machine -eq 0x8664) "Expected x64 artifact: $binary"
}
Assert-Check ((Get-FileHash -LiteralPath (Join-Path $distribution 'ProxyBridge.dll')).Hash -eq
    (Get-FileHash -LiteralPath (Join-Path $target 'native-proxybridge\ProxyBridge.dll')).Hash) 'Native build artifact mismatch'
$native = Get-PeInformation (Join-Path $distribution 'ProxyBridge.dll') $true
Assert-Check ($native.Machine -eq 0x8664) 'Native bridge is not x64'
$expectedExports = @('ProxyBridge_Start','ProxyBridge_Stop','ProxyBridge_SetOwnerSid',
    'ProxyBridge_AddProxyConfig','ProxyBridge_AddRule','ProxyBridge_SetTrafficLoggingEnabled',
    'ProxyBridge_GetTcpRelayPort','ProxyBridge_SetUpstreamReady')
foreach ($name in $expectedExports) {
    Assert-Check ($native.Exports -contains $name) "Missing native forwarding entrypoint: $name"
}
$pinned = @{
    'WinDivert.dll'='C1E060EE19444A259B2162F8AF0F3FE8C4428A1C6F694DCE20DE194AC8D7D9A2'
    'WinDivert64.sys'='8DA085332782708D8767BCACE5327A6EC7283C17CFB85E40B03CD2323A90DDC2'
    'codex-mihomo.exe'='3C107D54EF1B895E4980B53F517D52F3C1137101FA2637347C9CE343FC50D7B2'
}
foreach ($name in $pinned.Keys) {
    Assert-Check ((Get-FileHash -LiteralPath (Join-Path $distribution $name)).Hash -eq $pinned[$name]) "Pinned artifact mismatch: $name"
    Assert-Check ((Get-PeInformation (Join-Path $distribution $name)).Machine -eq 0x8664) "Expected x64 dependency: $name"
}
$driverSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $distribution 'WinDivert64.sys')
Assert-Check ($driverSignature.Status -eq 'Valid') 'Driver signature is not valid'
$identity = Get-Content -LiteralPath (Join-Path $distribution 'desktop-forwarding.json') -Raw | ConvertFrom-Json
Assert-Check ($identity.schema -eq 1) 'Desktop identity schema mismatch'
Assert-Check ((Get-FileHash -LiteralPath $identity.desktop_executable).Hash -eq $identity.desktop_sha256) 'Original desktop checksum mismatch'
Assert-Check ((Get-AuthenticodeSignature -LiteralPath $identity.desktop_executable).Status -eq 'Valid') 'Original desktop signature is not valid'
Assert-Check ((Get-FileHash -LiteralPath (Join-Path $distribution 'ProxyBridge.dll')).Hash -eq $identity.bridge_sha256) 'Configured forwarding library checksum mismatch'
Assert-Check (!(Test-Path -LiteralPath (Join-Path $distribution 'ChatGPT.exe'))) 'Release unexpectedly includes a copied desktop executable'

# Verify the builder's manifest before adding the final inspection report.
$manifest = Join-Path $distribution 'SHA256SUMS.txt'
$listed = @{}
foreach ($line in Get-Content -LiteralPath $manifest) {
    Assert-Check ($line -match '^([0-9a-fA-F]{64})  (.+)$') 'Malformed SHA256 manifest entry'
    $hash = $Matches[1]
    $name = $Matches[2]
    Assert-Check ([IO.Path]::GetFileName($name) -eq $name -and !$listed.ContainsKey($name)) 'Unsafe or duplicate manifest path'
    Assert-Check ((Get-FileHash -LiteralPath (Join-Path $distribution $name)).Hash -eq $hash) "Release manifest mismatch: $name"
    $listed[$name] = $true
}
foreach ($file in Get-ChildItem -LiteralPath $distribution -File) {
    if ($file.Name -ne 'SHA256SUMS.txt') {
        Assert-Check ($listed.ContainsKey($file.Name)) "Release artifact omitted from manifest: $($file.Name)"
    }
}
$nativeSourceArchive = Join-Path $distribution 'ProxyBridge-source.zip'
$source = Join-Path (Split-Path $PSScriptRoot -Parent) 'third_party\proxybridge'
if (!(Test-Path -LiteralPath $nativeSourceArchive)) {
    Compress-Archive -LiteralPath ((Get-ChildItem -LiteralPath $source -File).FullName) -DestinationPath $nativeSourceArchive
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($nativeSourceArchive)
try {
    foreach ($file in Get-ChildItem -LiteralPath $source -File) {
        $entry = $archive.GetEntry($file.Name)
        Assert-Check ($null -ne $entry -and $entry.Length -eq $file.Length) "Native source archive entry missing or truncated: $($file.Name)"
        $entryStream = $entry.Open()
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $entryHash = [BitConverter]::ToString($sha.ComputeHash($entryStream)).Replace('-','')
            Assert-Check ($entryHash -eq (Get-FileHash -LiteralPath $file.FullName).Hash) "Native source archive checksum mismatch: $($file.Name)"
        } finally { $entryStream.Dispose(); $sha.Dispose() }
    }
} finally { $archive.Dispose() }
$report = @{
    artifactChecksPassed=$true; checkedAt=[DateTimeOffset]::Now.ToString('o'); testsRun=$false
    runtimeTested=$false; driverLoadedForChecks=$false; freshBuild=$true
    compiledBinaries=$binaries; forwardingExports=$expectedExports
    driverSignature=[string]$driverSignature.Status; originalDesktopCopied=$false
    originalDesktopIdentityVerified=$true; targetDirectory=$target
}
[IO.File]::WriteAllText((Join-Path $distribution 'artifact-check.json'), ($report | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
Get-ChildItem -LiteralPath $distribution -File | Where-Object Name -ne 'SHA256SUMS.txt' | Sort-Object Name | ForEach-Object {
    '{0}  {1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash, $_.Name
} | Set-Content -LiteralPath $manifest
foreach ($line in Get-Content -LiteralPath $manifest) {
    Assert-Check ($line -match '^([0-9a-fA-F]{64})  (.+)$') 'Malformed final manifest entry'
    Assert-Check ((Get-FileHash -LiteralPath (Join-Path $distribution $Matches[2])).Hash -eq $Matches[1]) 'Final release manifest mismatch'
}
Write-Output 'Artifact checks passed. No binaries executed, drivers loaded, or network tests performed.'
