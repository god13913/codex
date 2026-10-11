param([string]$DistributionDirectory = '')
$ErrorActionPreference = 'Stop'
if (-not $DistributionDirectory) { throw 'Pass -DistributionDirectory.' }
$distribution = [IO.Path]::GetFullPath($DistributionDirectory)
$report = Get-Content -LiteralPath (Join-Path $distribution 'artifact-check.json') -Raw | ConvertFrom-Json
if ($report.artifactChecksPassed -ne $true -or $report.testsRun -ne $false) {
    throw 'Verified release artifacts are required before activation'
}
$executable = Join-Path $distribution 'codex.exe'
if (!(Test-Path -LiteralPath $executable -PathType Leaf)) { throw 'Verified CLI executable is missing' }
$runtime = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'runtime'
$backup = Join-Path $runtime ('cli-path-backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json')
$previous = [Environment]::GetEnvironmentVariable('CODEX_CLI_PATH','User')
@{ scope='User'; previous=$previous; replacement=$executable; recordedAt=[DateTimeOffset]::Now.ToString('o') } |
    ConvertTo-Json | Set-Content -LiteralPath $backup -Encoding utf8
[Environment]::SetEnvironmentVariable('CODEX_CLI_PATH',$executable,'User')
if ([Environment]::GetEnvironmentVariable('CODEX_CLI_PATH','User') -ne $executable) {
    throw 'User CODEX_CLI_PATH activation could not be confirmed'
}
@{ activated=$true; scope='User'; executable=$executable; environmentBackup=$backup;
   activatedAt=[DateTimeOffset]::Now.ToString('o'); effectiveAfterWindowsSignIn=$true } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runtime 'admin-release-activation.json') -Encoding utf8
Write-Output 'Verified release selected in the user CODEX_CLI_PATH. Effective at the next Windows sign-in.'
