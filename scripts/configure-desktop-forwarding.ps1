[CmdletBinding()]
param([Parameter(Mandatory)][string]$DistributionDirectory)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($DistributionDirectory)
$package = Get-AppxPackage -Name OpenAI.Codex | Sort-Object Version -Descending | Select-Object -First 1
if (!$package) { throw 'Installed official Codex desktop was not found' }
$desktop = Join-Path $package.InstallLocation 'app\ChatGPT.exe'
if ((Get-AuthenticodeSignature -LiteralPath $desktop).Status -ne 'Valid') {
    throw 'The original desktop executable does not have a valid publisher signature'
}
$configuration = @{
    schema=1
    desktop_package_family='OpenAI.Codex_2p2nqsd0c76g0'
    desktop_executable=$desktop
    desktop_sha256=(Get-FileHash -LiteralPath $desktop -Algorithm SHA256).Hash
    bridge_sha256=(Get-FileHash -LiteralPath (Join-Path $root 'ProxyBridge.dll') -Algorithm SHA256).Hash
} | ConvertTo-Json
[IO.File]::WriteAllText((Join-Path $root 'desktop-forwarding.json'), $configuration, [Text.UTF8Encoding]::new($false))
Write-Output 'Original desktop identity recorded; installation files were not changed.'
