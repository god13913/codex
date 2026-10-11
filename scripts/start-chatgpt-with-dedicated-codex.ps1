[CmdletBinding()]
param(
    [string]$CodexCliPath,
    [switch]$CheckOnly,
    [int]$VerifyTimeoutSeconds = 20
)

$ErrorActionPreference = 'Stop'

function Resolve-ExistingFile {
    param([Parameter(Mandatory)][string[]]$Candidates)

    foreach ($candidate in $Candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        $expanded = [Environment]::ExpandEnvironmentVariables($candidate)
        if (Test-Path -LiteralPath $expanded -PathType Leaf) {
            return [IO.Path]::GetFullPath($expanded)
        }
    }

    return $null
}

function Get-ChatGptExecutable {
    $running = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -ieq 'ChatGPT.exe' -and
            $_.ExecutablePath -like 'C:\Program Files\WindowsApps\OpenAI.Codex_*\app\ChatGPT.exe'
        })

    $runningMain = $running |
        Where-Object { $_.CommandLine -notmatch '--type=' } |
        Select-Object -First 1
    if ($runningMain -and (Test-Path -LiteralPath $runningMain.ExecutablePath -PathType Leaf)) {
        return [IO.Path]::GetFullPath($runningMain.ExecutablePath)
    }

    $package = Get-AppxPackage -Name 'OpenAI.Codex' -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending |
        Select-Object -First 1
    if ($package) {
        $candidate = Join-Path $package.InstallLocation 'app\ChatGPT.exe'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return [IO.Path]::GetFullPath($candidate)
        }
    }

    $fallback = Get-ChildItem -LiteralPath 'C:\Program Files\WindowsApps' -Directory -Filter 'OpenAI.Codex_*' -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending |
        ForEach-Object { Join-Path $_.FullName 'app\ChatGPT.exe' } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
    if ($fallback) {
        return [IO.Path]::GetFullPath($fallback)
    }

    return $null
}

function Get-ChatGptMainProcesses {
    @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -ieq 'ChatGPT.exe' -and
            $_.ExecutablePath -like 'C:\Program Files\WindowsApps\OpenAI.Codex_*\app\ChatGPT.exe' -and
            $_.CommandLine -notmatch '--type='
        })
}

function Get-DescendantProcesses {
    param([Parameter(Mandatory)][int]$RootPid)

    $all = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    $result = @()
    $frontier = @([uint32]$RootPid)
    $seen = [Collections.Generic.HashSet[uint32]]::new()
    $null = $seen.Add([uint32]$RootPid)

    while ($frontier.Count -gt 0) {
        $next = @(
            $all | Where-Object {
                $parent = [uint32]$_.ParentProcessId
                ($frontier -contains $parent) -and $seen.Add([uint32]$_.ProcessId)
            }
        )
        if ($next.Count -eq 0) {
            break
        }
        $result += $next
        $frontier = @($next | ForEach-Object { [uint32]$_.ProcessId })
    }

    return $result
}

$scriptDirectory = [IO.Path]::GetFullPath($PSScriptRoot)
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $scriptDirectory '..\..'))
$defaultCliCandidates = @(
    (Join-Path $repositoryRoot 'release\CodexDedicated\codex.exe'),
    (Join-Path $scriptDirectory 'codex.exe')
)

$resolvedCli = if ([string]::IsNullOrWhiteSpace($CodexCliPath)) {
    Resolve-ExistingFile -Candidates $defaultCliCandidates
} else {
    Resolve-ExistingFile -Candidates @($CodexCliPath)
}

if (-not $resolvedCli) {
    throw "Dedicated Codex CLI was not found. Default path: $($defaultCliCandidates[0]). Use -CodexCliPath to specify codex.exe."
}

$resolvedCli = [IO.Path]::GetFullPath($resolvedCli)
$cliDirectory = Split-Path -Parent $resolvedCli
$chatGptExecutable = Get-ChatGptExecutable

if (-not $chatGptExecutable) {
    throw 'ChatGPT desktop was not found. Confirm that the Microsoft Store version is installed.'
}

$runningMain = @(Get-ChatGptMainProcesses)

Write-Host "ChatGPT: $chatGptExecutable"
Write-Host "Temporary Codex CLI: $resolvedCli"
Write-Host 'Scope: only this ChatGPT process and its children; no user/system environment variable is persisted.'

if ($CheckOnly) {
    if ($runningMain.Count -gt 0) {
        Write-Host "ChatGPT is already running (PID: $($runningMain[0].ProcessId)). Check passed, but the new variable cannot affect that instance."
    } else {
        Write-Host 'No ChatGPT main process is running; the temporary instance can be started.'
    }
    exit 0
}

if ($runningMain.Count -gt 0) {
    $pids = ($runningMain | ForEach-Object { $_.ProcessId }) -join ', '
    throw "ChatGPT is already running (PID: $pids). Exit the desktop app normally, then run this script again. The script will not force-close an existing session."
}

# The desktop application reads this variable when it selects the CLI. PATH is
# also prefixed so helper processes launched by the selected CLI resolve the
# bundled Mihomo and admin binaries from the same distribution directory.
$env:CODEX_CLI_PATH = $resolvedCli
$env:PATH = "$cliDirectory;$env:PATH"

$desktopProcess = Start-Process -FilePath $chatGptExecutable `
    -WorkingDirectory (Split-Path -Parent $chatGptExecutable) `
    -PassThru

Write-Host "ChatGPT started (main PID: $($desktopProcess.Id)). Verifying the Codex CLI it actually starts..."

$deadline = [DateTime]::UtcNow.AddSeconds([Math]::Max(1, $VerifyTimeoutSeconds))
$actualCodex = $null
do {
    Start-Sleep -Milliseconds 500
    $descendants = @(Get-DescendantProcesses -RootPid $desktopProcess.Id)
    $actualCodex = $descendants |
        Where-Object { $_.Name -ieq 'codex.exe' -and $_.ExecutablePath } |
        Select-Object -First 1
} while (-not $actualCodex -and [DateTime]::UtcNow -lt $deadline)

if (-not $actualCodex) {
    Write-Warning 'codex.exe was not observed before the verification timeout. Check whether the desktop app is still initializing.'
    exit 3
}

$actualPath = [IO.Path]::GetFullPath($actualCodex.ExecutablePath)
if (-not [StringComparer]::OrdinalIgnoreCase.Equals($actualPath, $resolvedCli)) {
    Write-Warning "ChatGPT actually started: $actualPath"
    Write-Warning 'CODEX_CLI_PATH did not override this desktop launch; the script will not report success.'
    exit 4
}

Write-Host "Verification succeeded: ChatGPT -> $actualPath"
Write-Host 'After ChatGPT closes, this temporary variable and proxy child process end with it; normal launches use the default CLI again.'
