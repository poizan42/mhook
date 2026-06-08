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

.PARAMETER TimeoutSeconds
    Maximum seconds to wait for each test binary before killing it.  Defaults to 10.

.PARAMETER Arch
    Architectures to build and test.  Defaults to all ('x64', 'x86').
    Mutually exclusive with -Target.

.PARAMETER Configuration
    Build configurations to build and test.  Defaults to all
    ('Debug', 'DebugDynamic', 'Release', 'ReleaseDynamic').
    Mutually exclusive with -Target.

.PARAMETER Target
    Explicit arch/config combinations to build and test, e.g. 'x64/Release', 'x86/Debug'.
    Mutually exclusive with -Arch and -Configuration.

.NOTES
    Exit code is 0 if every build succeeds and every test passes, 1 otherwise.
#>
[CmdletBinding(DefaultParameterSetName = 'CrossProduct')]
param(
    [Parameter(ParameterSetName = 'CrossProduct')]
    [Parameter(ParameterSetName = 'Target')]
    [string]$SolutionDir = $PSScriptRoot,

    [Parameter(ParameterSetName = 'CrossProduct')]
    [Parameter(ParameterSetName = 'Target')]
    [switch]$NoBuild,

    [Parameter(ParameterSetName = 'CrossProduct')]
    [Parameter(ParameterSetName = 'Target')]
    [string]$Filter = '*',

    [Parameter(ParameterSetName = 'CrossProduct')]
    [Parameter(ParameterSetName = 'Target')]
    [int]$TimeoutSeconds = 10,

    [Parameter(ParameterSetName = 'CrossProduct')]
    [ValidateSet('x64', 'x86')]
    [string[]]$Arch = @('x64', 'x86'),

    [Parameter(ParameterSetName = 'CrossProduct')]
    [ValidateSet('Debug', 'DebugDynamic', 'Release', 'ReleaseDynamic')]
    [string[]]$Configuration = @('Debug', 'DebugDynamic', 'Release', 'ReleaseDynamic'),

    [Parameter(ParameterSetName = 'Target')]
    [ValidateSet('x64/Debug', 'x64/DebugDynamic', 'x64/Release', 'x64/ReleaseDynamic',
                 'x86/Debug', 'x86/DebugDynamic', 'x86/Release', 'x86/ReleaseDynamic')]
    [string[]]$Target
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
# Run a test executable with a timeout, returning output lines and exit info.
# Async reads are started before WaitForExit to prevent pipe-buffer deadlock.
# ---------------------------------------------------------------------------
function Invoke-TestExe([string]$Exe, [string]$Filter, [int]$TimeoutSeconds) {
    $psi = [System.Diagnostics.ProcessStartInfo]::new($Exe, "--gtest_filter=$Filter")
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow         = $true

    $proc = [System.Diagnostics.Process]::Start($psi)

    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()

    $finished = $proc.WaitForExit($TimeoutSeconds * 1000)
    if (-not $finished) {
        $proc.Kill($true)   # kills process tree (PS 7+ / .NET 5+)
        $proc.WaitForExit()
    }
    [System.Threading.Tasks.Task]::WhenAll($stdoutTask, $stderrTask).Wait()

    return [pscustomobject]@{
        Lines    = ($stdoutTask.Result + $stderrTask.Result) -split '\r?\n'
        ExitCode = if ($finished) { $proc.ExitCode } else { -1 }
        TimedOut = -not $finished
    }
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

if ($PSCmdlet.ParameterSetName -eq 'Target') {
    $configs = $configs | Where-Object { "$($_.MSBuildPlatform)/$($_.MSBuildConfig)" -in $Target }
} else {
    $configs = $configs | Where-Object { $_.MSBuildPlatform -in $Arch -and $_.MSBuildConfig -in $Configuration }
}
if ($configs.Count -eq 0) {
    Write-Error 'No configurations selected.  Check -Arch, -Configuration, and -Target.'
    exit 1
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$sln = Join-Path $SolutionDir 'libmhook.slnx'
if (-not (Test-Path $sln)) { Write-Error "Solution not found: $sln"; exit 1 }

if (-not $NoBuild) {
    $buildParams = if ($PSCmdlet.ParameterSetName -eq 'Target') {
        @{ Target = $Target }
    } else {
        @{ Arch = $Arch; Configuration = $Configuration }
    }
    & (Join-Path $PSScriptRoot 'build.ps1') -SolutionDir $SolutionDir @buildParams
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
            $run    = Invoke-TestExe -Exe $testExe -Filter $Filter -TimeoutSeconds $TimeoutSeconds
            $ok     = -not $run.TimedOut -and $run.ExitCode -eq 0
            $counts = Get-GtestCounts $run.Lines
            $total  = $counts.Passed + $counts.Failed

            if ($run.TimedOut) {
                $testStatus = 'TIMEOUT'
                Write-Host " TIMEOUT (>${TimeoutSeconds}s)" -ForegroundColor Yellow
            } elseif ($ok) {
                $testStatus = 'PASS'
                $testDetail = "$($counts.Passed)/$total"
                Write-Host " PASS ($($counts.Passed)/$total)"
            } else {
                $testStatus = 'FAIL'
                $testDetail = "$($counts.Passed)/$total"
                Write-Host " FAIL ($($counts.Passed)/$total)"
                # Show failing test names
                $run.Lines | Where-Object { $_ -match '^\[  FAILED  \]' } |
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

    $colour = if ($r.Build -eq 'FAILED' -or $r.TestStatus -in 'FAIL', 'TIMEOUT') { 'Red' }
              elseif ($r.TestStatus -eq 'PASS')                                    { 'Green' }
              else                                                                  { 'White' }
    Write-Host $line -ForegroundColor $colour
}

Write-Host ''

$nBuilt   = @($results | Where-Object { $_.Build      -eq 'OK'      }).Count
$nPass    = @($results | Where-Object { $_.TestStatus -eq 'PASS'    }).Count
$nFail    = @($results | Where-Object { $_.TestStatus -eq 'FAIL'    }).Count
$nTimeout = @($results | Where-Object { $_.TestStatus -eq 'TIMEOUT' }).Count
$nBuildF  = @($results | Where-Object { $_.Build      -eq 'FAILED'  }).Count

$total = $results.Count
Write-Host "$total configurations: $nBuilt built, $nPass passed, $nFail failed" -NoNewline
if ($nTimeout -gt 0) { Write-Host ", $nTimeout timed out" -NoNewline }
if ($nBuildF  -gt 0) { Write-Host ", $nBuildF build failure(s)" -NoNewline }
Write-Host ''

$allOk = ($nBuildF -eq 0 -and $nFail -eq 0 -and $nTimeout -eq 0)
if ($allOk) {
    Write-Host 'All checks passed.' -ForegroundColor Green
} else {
    Write-Host 'One or more checks FAILED.' -ForegroundColor Red
}

exit ($allOk ? 0 : 1)
