<#
.SYNOPSIS
    Runs the mhook unit tests for all 8 platform/configuration combinations.

.DESCRIPTION
    Runs mhook-unit-tests.exe for each configuration against existing build
    artifacts and prints a summary table at the end showing test pass/fail
    counts for every combination.

.PARAMETER SolutionDir
    Root of the mhook repository.  Defaults to the directory containing this script.

.PARAMETER Filter
    Google Test filter passed as --gtest_filter.  Defaults to '*' (run all tests).

.NOTES
    Exit code is 0 if every test passes, 1 otherwise.
    Run build.ps1 first to produce the test binaries.
#>
[CmdletBinding()]
param(
    [string]$SolutionDir = $PSScriptRoot,
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

Write-Host "Solution: $sln"
Write-Host ''

$results = @()

foreach ($cfg in $configs) {
    $label   = "$($cfg.MSBuildConfig)|$($cfg.OutArch)"
    $testExe = Join-Path $SolutionDir "build" "artifacts" "mhook-unit-tests" $cfg.OutDir "mhook-unit-tests.exe"

    $testStatus = $null
    $testDetail = $null

    if (-not (Test-Path $testExe)) {
        $testStatus = 'MISSING'
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

    $results += [pscustomobject]@{
        Arch       = $cfg.OutArch
        Config     = $cfg.MSBuildConfig
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
$testWidth   = ($results | ForEach-Object { $_.TestStatus.Length } | Measure-Object -Max).Maximum
$detailWidth = 7

$header = "  {0,-$archWidth}  {1,-$configWidth}  {2,-$testWidth}  {3,-$detailWidth}" `
    -f 'Arch', 'Config', 'Tests', 'Pass/N'
$sep    = "  {0}  {1}  {2}  {3}" `
    -f ('-' * $archWidth), ('-' * $configWidth), ('-' * $testWidth), ('-' * $detailWidth)

Write-Host $header
Write-Host $sep

foreach ($r in $results) {
    $detailCol = if ($r.TestDetail) { $r.TestDetail } else { '' }
    $line      = "  {0,-$archWidth}  {1,-$configWidth}  {2,-$testWidth}  {3,-$detailWidth}" `
        -f $r.Arch, $r.Config, $r.TestStatus, $detailCol

    $colour = if ($r.TestStatus -eq 'FAIL')    { 'Red' }
              elseif ($r.TestStatus -eq 'PASS') { 'Green' }
              else                               { 'White' }
    Write-Host $line -ForegroundColor $colour
}

Write-Host ''

$nPass    = @($results | Where-Object { $_.TestStatus -eq 'PASS'    }).Count
$nFail    = @($results | Where-Object { $_.TestStatus -eq 'FAIL'    }).Count
$nMissing = @($results | Where-Object { $_.TestStatus -eq 'MISSING' }).Count
$total    = $results.Count

Write-Host "$total configurations: $nPass passed, $nFail failed" -NoNewline
if ($nMissing -gt 0) { Write-Host ", $nMissing missing exe" -NoNewline }
Write-Host ''

$allOk = ($nFail -eq 0 -and $nMissing -eq 0)
if ($allOk) {
    Write-Host 'All tests passed.' -ForegroundColor Green
} else {
    Write-Host 'One or more tests FAILED.' -ForegroundColor Red
}

exit ($allOk ? 0 : 1)
