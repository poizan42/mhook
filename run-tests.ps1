<#
.SYNOPSIS
    Builds and runs the mhook unit tests for all 8 platform/configuration combinations.

.DESCRIPTION
    By default builds the solution via build.ps1, then runs mhook-unit-tests.exe for
    each configuration.  Prints a summary table at the end showing build status and
    test pass/fail counts for every combination.

.PARAMETER SolutionDir
    Root of the mhook repository.  Defaults to the directory containing this script.

.PARAMETER NoBuild
    Skip the build step and run only the tests against existing binaries.

.PARAMETER Filter
    Google Test filter passed as --gtest_filter.  Defaults to '*' (run all tests).

.NOTES
    Exit code is 0 if every build succeeds and every test passes, 1 otherwise.
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
    & (Join-Path $PSScriptRoot 'build.ps1') -SolutionDir $SolutionDir
    if ($LASTEXITCODE -ne 0) { Write-Host '' }  # blank line before test section on build failure
}

Write-Host ''

$results = @()

foreach ($cfg in $configs) {
    $label   = "$($cfg.MSBuildConfig)|$($cfg.OutArch)"
    $testExe = Join-Path $SolutionDir "build" "artifacts" "mhook-unit-tests" $cfg.OutDir "mhook-unit-tests.exe"

    $buildStatus = if ($NoBuild)              { 'SKIP' }
                   elseif (Test-Path $testExe) { 'OK'   }
                   else                        { 'FAILED' }

    $testStatus = $null
    $testDetail = $null

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
        Arch       = $cfg.OutArch
        Config     = $cfg.MSBuildConfig
        Build      = $buildStatus
        TestStatus = $testStatus
        TestDetail = $testDetail
    }
}

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '=== Summary ==='
Write-Host ''

$archWidth   = ($results | ForEach-Object { $_.Arch.Length }       | Measure-Object -Max).Maximum
$configWidth = ($results | ForEach-Object { $_.Config.Length }     | Measure-Object -Max).Maximum
$buildWidth  = 6
$testWidth   = ($results | ForEach-Object { $_.TestStatus.Length } | Measure-Object -Max).Maximum
$detailWidth = 7

$header = "  {0,-$archWidth}  {1,-$configWidth}  {2,-$buildWidth}  {3,-$testWidth}  {4,-$detailWidth}" `
    -f 'Arch', 'Config', 'Build', 'Tests', 'Pass/N'
$sep    = "  {0}  {1}  {2}  {3}  {4}" `
    -f ('-' * $archWidth), ('-' * $configWidth), ('-' * $buildWidth), ('-' * $testWidth), ('-' * $detailWidth)

Write-Host $header
Write-Host $sep

foreach ($r in $results) {
    $detailCol = if ($r.TestDetail) { $r.TestDetail } else { '' }
    $line      = "  {0,-$archWidth}  {1,-$configWidth}  {2,-$buildWidth}  {3,-$testWidth}  {4,-$detailWidth}" `
        -f $r.Arch, $r.Config, $r.Build, $r.TestStatus, $detailCol

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
