<#
.SYNOPSIS
    Builds and runs the mhook unit tests for all 8 platform/configuration combinations.

.DESCRIPTION
    Builds the solution for every configuration, then runs mhook-unit-tests.exe
    for each configuration that built successfully.  Prints a summary table at
    the end showing build status and test pass/fail counts for every combination.

.PARAMETER SolutionDir
    Root of the mhook repository.  Defaults to the directory containing this script.

.PARAMETER NoBuild
    Skip the build step and run only the tests against existing binaries.

.PARAMETER Filter
    Google Test filter passed as --gtest_filter.  Defaults to '*' (run all tests).

.NOTES
    Exit code is 0 if every configured build succeeds and every test passes,
    1 otherwise.
#>
[CmdletBinding()]
param(
    [string]$SolutionDir = $PSScriptRoot,
    [switch]$NoBuild,
    [string]$Filter = '*'
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
# Parse Google Test stdout for pass/fail counts
# ---------------------------------------------------------------------------
function Get-GtestCounts([string[]]$Lines) {
    $passed = 0; $failed = 0
    foreach ($line in $Lines) {
        if ($line -match '\[\s+PASSED\s+\]\s+(\d+) test')  { $passed = [int]$Matches[1] }
        if ($line -match '\[\s+FAILED\s+\]\s+(\d+) test')  { $failed = [int]$Matches[1] }
    }
    return @{ Passed = $passed; Failed = $failed }
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

if (-not $NoBuild) {
    try   { $msbuild = Find-MSBuild }
    catch { Write-Error $_.Exception.Message; exit 1 }
    Write-Host "MSBuild : $msbuild"
}

Write-Host "Solution: $sln"
Write-Host ''

$results = @()

foreach ($cfg in $configs) {
    $label    = "$($cfg.MSBuildConfig)|$($cfg.OutArch)"
    $testExe  = Join-Path $SolutionDir "$($cfg.OutDir)\mhook-unit-tests.exe"

    $buildStatus = $null
    $testStatus  = $null
    $testDetail  = $null

    # --- Build ---
    if ($NoBuild) {
        $buildStatus = if (Test-Path $testExe) { 'SKIP' } else { 'MISSING' }
    } else {
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
    }

    # --- Test ---
    if ($buildStatus -in 'OK', 'SKIP') {
        if (-not (Test-Path $testExe)) {
            $testStatus = 'NO EXE'
        } else {
            Write-Host "  Testing  $label ..." -NoNewline
            $testOut = & $testExe --gtest_filter=$Filter 2>&1
            $ok      = $LASTEXITCODE -eq 0
            $counts  = Get-GtestCounts $testOut
            $total   = $counts.Passed + $counts.Failed

            if ($ok) {
                $testStatus = 'PASS'
                $testDetail = "$($counts.Passed)/$total"
                Write-Host " PASS ($($counts.Passed)/$total)"
            } else {
                $testStatus = 'FAIL'
                $testDetail = "$($counts.Passed)/$total"
                Write-Host " FAIL ($($counts.Passed)/$total)"
                # Show failing test names
                $testOut | Where-Object { $_ -match '^\[  FAILED  \]' } |
                    Select-Object -First 10 |
                    ForEach-Object { Write-Host "    $_" }
            }
        }
    } else {
        $testStatus = '-'
    }

    $results += [pscustomobject]@{
        Label       = $label
        Arch        = $cfg.OutArch
        Config      = $cfg.MSBuildConfig
        Build       = $buildStatus
        TestStatus  = $testStatus
        TestDetail  = $testDetail
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
$testWidth   = ($results | ForEach-Object { $_.TestStatus.Length } | Measure-Object -Max).Maximum
$detailWidth = 7

$header = "  {0,-$archWidth}  {1,-$configWidth}  {2,-$buildWidth}  {3,-$testWidth}  {4,-$detailWidth}" `
    -f 'Arch','Config','Build','Tests','Pass/N'
$sep    = "  {0}  {1}  {2}  {3}  {4}" `
    -f ('-' * $archWidth), ('-' * $configWidth), ('-' * $buildWidth), ('-' * $testWidth), ('-' * $detailWidth)

Write-Host $header
Write-Host $sep

foreach ($r in $results) {
    $buildCol  = $r.Build
    $testCol   = $r.TestStatus
    $detailCol = if ($r.TestDetail) { $r.TestDetail } else { '' }

    $line = "  {0,-$archWidth}  {1,-$configWidth}  {2,-$buildWidth}  {3,-$testWidth}  {4,-$detailWidth}" `
        -f $r.Arch, $r.Config, $buildCol, $testCol, $detailCol

    $colour = if ($r.Build -eq 'FAILED' -or $r.TestStatus -eq 'FAIL') { 'Red' }
              elseif ($r.TestStatus -eq 'PASS')                         { 'Green' }
              else                                                        { 'White' }
    Write-Host $line -ForegroundColor $colour
}

Write-Host ''

$nBuilt  = @($results | Where-Object { $_.Build      -eq 'OK'     }).Count
$nPass   = @($results | Where-Object { $_.TestStatus -eq 'PASS'   }).Count
$nFail   = @($results | Where-Object { $_.TestStatus -eq 'FAIL'   }).Count
$nBuildF = @($results | Where-Object { $_.Build      -eq 'FAILED' }).Count

$total   = $results.Count
Write-Host "$total configurations: $nBuilt built, $nPass passed, $nFail failed" -NoNewline
if ($nBuildF -gt 0) { Write-Host ", $nBuildF build failure(s)" -NoNewline }
Write-Host ''

$allOk = ($nBuildF -eq 0 -and $nFail -eq 0)
if ($allOk) {
    Write-Host 'All checks passed.' -ForegroundColor Green
} else {
    Write-Host 'One or more checks FAILED.' -ForegroundColor Red
}

exit ($allOk ? 0 : 1)
