<#
.SYNOPSIS
    Builds the mhook solution for all 8 platform/configuration combinations.

.DESCRIPTION
    Builds the solution for every configuration and prints a summary table at
    the end showing the build status for every combination.

.PARAMETER SolutionDir
    Root of the mhook repository.  Defaults to the directory containing this script.

.NOTES
    Exit code is 0 if every configured build succeeds, 1 otherwise.
#>
[CmdletBinding()]
param(
    [string]$SolutionDir = $PSScriptRoot
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
# Locate MSBuild via vswhere
# ---------------------------------------------------------------------------
function Find-MSBuild {
    $vsWhere = Join-Path ${env:ProgramFiles(x86)} `
        'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vsWhere)) { throw "vswhere.exe not found at $vsWhere" }

    # Require VC tools to select a proper VS installation, not other products
    # (e.g. SQL Server Management Studio) that also ship an MSBuild.
    $vsPath = & $vsWhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath 2>$null
    if (-not $vsPath) { throw "vswhere: no VS installation with VC tools found" }

    $msbuild = Join-Path $vsPath 'MSBuild\Current\Bin\MSBuild.exe'
    if (-not (Test-Path $msbuild)) { throw "MSBuild.exe not found at $msbuild" }
    return $msbuild
}

# ---------------------------------------------------------------------------
# Configurations
# ---------------------------------------------------------------------------
$configs = @(
    [pscustomobject]@{ MSBuildPlatform = 'x64';   MSBuildConfig = 'Debug';          OutArch = 'x64';   OutDir = 'x64\Debug' }
    [pscustomobject]@{ MSBuildPlatform = 'x64';   MSBuildConfig = 'DebugDynamic';   OutArch = 'x64';   OutDir = 'x64\DebugDynamic' }
    [pscustomobject]@{ MSBuildPlatform = 'x64';   MSBuildConfig = 'Release';        OutArch = 'x64';   OutDir = 'x64\Release' }
    [pscustomobject]@{ MSBuildPlatform = 'x64';   MSBuildConfig = 'ReleaseDynamic'; OutArch = 'x64';   OutDir = 'x64\ReleaseDynamic' }
    [pscustomobject]@{ MSBuildPlatform = 'x86';   MSBuildConfig = 'Debug';          OutArch = 'Win32'; OutDir = 'Win32\Debug' }
    [pscustomobject]@{ MSBuildPlatform = 'x86';   MSBuildConfig = 'DebugDynamic';   OutArch = 'Win32'; OutDir = 'Win32\DebugDynamic' }
    [pscustomobject]@{ MSBuildPlatform = 'x86';   MSBuildConfig = 'Release';        OutArch = 'Win32'; OutDir = 'Win32\Release' }
    [pscustomobject]@{ MSBuildPlatform = 'x86';   MSBuildConfig = 'ReleaseDynamic'; OutArch = 'Win32'; OutDir = 'Win32\ReleaseDynamic' }
)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$sln = Join-Path $SolutionDir 'libmhook.slnx'
if (-not (Test-Path $sln)) { Write-Error "Solution not found: $sln"; exit 1 }

try   { $msbuild = Find-MSBuild }
catch { Write-Error $_.Exception.Message; exit 1 }
Write-Host "MSBuild : $msbuild"
Write-Host "Solution: $sln"
Write-Host ''

$results = @()

foreach ($cfg in $configs) {
    $label = "$($cfg.MSBuildConfig)|$($cfg.OutArch)"

    Write-Host "  Building $label ..." -NoNewline
    $buildOut = & $msbuild $sln `
        /p:Configuration=$($cfg.MSBuildConfig) `
        /p:Platform=$($cfg.MSBuildPlatform) `
        /m /nologo /verbosity:quiet 2>&1
    if ($LASTEXITCODE -eq 0) {
        $buildStatus = 'OK'
        Write-Host ' OK'
    } else {
        $buildStatus = 'FAILED'
        Write-Host ' FAILED'
        $buildOut | Where-Object { $_ -match '\berror\b' } |
            Select-Object -Unique | Select-Object -First 3 |
            ForEach-Object { Write-Host "    $_" }
    }

    $results += [pscustomobject]@{
        Arch    = $cfg.OutArch
        Config  = $cfg.MSBuildConfig
        Build   = $buildStatus
    }
}

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '=== Summary ==='
Write-Host ''

$archWidth   = ($results | ForEach-Object { $_.Arch.Length }   | Measure-Object -Max).Maximum
$configWidth = ($results | ForEach-Object { $_.Config.Length } | Measure-Object -Max).Maximum
$buildWidth  = 6

$header = "  {0,-$archWidth}  {1,-$configWidth}  {2,-$buildWidth}" `
    -f 'Arch', 'Config', 'Build'
$sep    = "  {0}  {1}  {2}" `
    -f ('-' * $archWidth), ('-' * $configWidth), ('-' * $buildWidth)

Write-Host $header
Write-Host $sep

foreach ($r in $results) {
    $line   = "  {0,-$archWidth}  {1,-$configWidth}  {2,-$buildWidth}" `
        -f $r.Arch, $r.Config, $r.Build
    $colour = if ($r.Build -eq 'FAILED') { 'Red' } else { 'Green' }
    Write-Host $line -ForegroundColor $colour
}

Write-Host ''

$nBuilt  = @($results | Where-Object { $_.Build -eq 'OK'     }).Count
$nFailed = @($results | Where-Object { $_.Build -eq 'FAILED' }).Count
$total   = $results.Count

Write-Host "$total configurations: $nBuilt built" -NoNewline
if ($nFailed -gt 0) { Write-Host ", $nFailed failed" -NoNewline }
Write-Host ''

$allOk = $nFailed -eq 0
if ($allOk) {
    Write-Host 'All builds passed.' -ForegroundColor Green
} else {
    Write-Host 'One or more builds FAILED.' -ForegroundColor Red
}

exit ($allOk ? 0 : 1)
