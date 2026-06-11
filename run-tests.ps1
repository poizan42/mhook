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

.PARAMETER Repeat
    Number of times to run each test configuration.  Defaults to 1.  Use a higher
    value to catch flaky tests: each iteration's artifacts are deleted immediately
    after it passes (unless -KeepResults is set), so only failing iterations keep
    files on disk.

.PARAMETER Parallel
    Maximum number of test-exe runs to execute concurrently.  Defaults to 1
    (fully sequential — identical to before).  Values > 1 dispatch the flat
    (iteration x configuration) work list through a runspace pool, which speeds up
    a stress pass (especially with -Repeat) and increases CPU/timing contention so
    timing-sensitive races reproduce more readily.  Composes with -Trace and -Cdb
    (each run records its own trace / debugs into its own results subfolder) — mind
    the extra I/O for TTD and the N-debuggers load for CDB.  -StopOnFailure becomes
    best-effort (in-flight runs finish; queued ones are skipped).  Under heavy
    parallelism raise -TimeoutSeconds to avoid spurious timeouts.

.PARAMETER ResultsDir
    Directory under which a timestamped subfolder is created for each invocation.
    Defaults to 'test-results' alongside this script.

.PARAMETER KeepResults
    Keep the run subfolder even when all tests pass.  By default it is deleted on
    a fully successful run.

.PARAMETER Trace
    Wrap each test executable in ttd.exe to capture a Time Travel Debugging trace.
    Trace files (.run) are saved alongside the log files and follow the same
    keep/cleanup rules as other artifacts.
    Requires administrative privileges — ttd.exe will fail and the script will
    exit early if the session is not elevated.
    Mutually exclusive with -Cdb.

.PARAMETER Cdb
    Path to a CDB commands file.  Each test executable is launched under
    cdbX64.exe (x64) or cdbX86.exe (x86) with -g -G -cf <script>.
    The script runs at attach time; use it to set exception handlers, break
    on access violations, capture dumps, etc.  Test results are read from a
    GTest JSON file so CDB's own output does not interfere with pass/fail
    counting.  Mutually exclusive with -Trace.
    Does not require administrative privileges.

.PARAMETER CdbArgs
    Extra command-line options forwarded verbatim to cdb, inserted before the
    target executable.  For example, -CdbArgs '-o' enables child-process
    debugging.  Requires -Cdb.

.PARAMETER StopOnFailure
    Stop after the first test failure or timeout.  Useful with -Repeat and
    -Trace to capture a TTD trace from the first failing iteration without
    wasting time on subsequent runs.

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
[CmdletBinding(DefaultParameterSetName = 'Matrix')]
param(
    [Parameter(ParameterSetName = 'Matrix')]
    [Parameter(ParameterSetName = 'Target')]
    [string]$SolutionDir = $PSScriptRoot,

    [Parameter(ParameterSetName = 'Matrix')]
    [Parameter(ParameterSetName = 'Target')]
    [switch]$NoBuild,

    [Parameter(ParameterSetName = 'Matrix')]
    [Parameter(ParameterSetName = 'Target')]
    [string]$Filter = '*',

    [Parameter(ParameterSetName = 'Matrix')]
    [Parameter(ParameterSetName = 'Target')]
    [int]$TimeoutSeconds = 10,

    [Parameter(ParameterSetName = 'Matrix')]
    [Parameter(ParameterSetName = 'Target')]
    [int]$Repeat = 1,

    [Parameter(ParameterSetName = 'Matrix')]
    [Parameter(ParameterSetName = 'Target')]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$Parallel = 1,

    [Parameter(ParameterSetName = 'Matrix')]
    [Parameter(ParameterSetName = 'Target')]
    [string]$ResultsDir = (Join-Path $PSScriptRoot 'test-results'),

    [Parameter(ParameterSetName = 'Matrix')]
    [Parameter(ParameterSetName = 'Target')]
    [switch]$KeepResults,

    [Parameter(ParameterSetName = 'Matrix')]
    [Parameter(ParameterSetName = 'Target')]
    [switch]$Trace,

    [Parameter(ParameterSetName = 'Matrix')]
    [Parameter(ParameterSetName = 'Target')]
    [string]$Cdb = '',

    [Parameter(ParameterSetName = 'Matrix')]
    [Parameter(ParameterSetName = 'Target')]
    [string[]]$CdbArgs = @(),

    [Parameter(ParameterSetName = 'Matrix')]
    [Parameter(ParameterSetName = 'Target')]
    [switch]$StopOnFailure,

    [Parameter(ParameterSetName = 'Matrix')]
    [ValidateSet('x64', 'x86')]
    [string[]]$Arch = @('x64', 'x86'),

    [Parameter(ParameterSetName = 'Matrix')]
    [ValidateSet('Debug', 'DebugDynamic', 'Release', 'ReleaseDynamic')]
    [string[]]$Configuration = @('Debug', 'DebugDynamic', 'Release', 'ReleaseDynamic'),

    [Parameter(ParameterSetName = 'Target')]
    [ValidateSet('x64/Debug', 'x64/DebugDynamic', 'x64/Release', 'x64/ReleaseDynamic',
                 'x86/Debug', 'x86/DebugDynamic', 'x86/Release', 'x86/ReleaseDynamic')]
    [string[]]$Target
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Continue'

# Compile a small C# helper once per session.  PowerShell script blocks cannot
# run on thread-pool threads (no runspace), so we use a plain .NET method for
# the concurrent stream reads.
if (-not ([System.Management.Automation.PSTypeName]'MhookStreamInterleaver').Type) {
    Add-Type -TypeDefinition @'
using System.Collections.Concurrent;
using System.IO;
using System.Threading.Tasks;
public static class MhookStreamInterleaver {
    public static Task Drain(TextReader reader, ConcurrentQueue<string> queue) {
        return Task.Run(() => {
            string line;
            while ((line = reader.ReadLine()) != null) queue.Enqueue(line);
        });
    }
}
'@
}

# ---------------------------------------------------------------------------
# Locate ttd.exe: PATH first, then the known WindowsApps fallback location.
# ---------------------------------------------------------------------------
function Find-Ttd {
    $onPath = Get-Command ttd.exe -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    $fallback = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\ttd.exe'
    if (Test-Path $fallback) { return $fallback }
    return $null
}

# ---------------------------------------------------------------------------
# Locate cdbX64.exe / cdbX86.exe: PATH first, then WindowsApps fallback.
# ---------------------------------------------------------------------------
function Find-Cdb([string]$OutArch) {
    $name = if ($OutArch -eq 'x64') { 'cdbX64.exe' } else { 'cdbX86.exe' }
    $onPath = Get-Command $name -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    $fallback = Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\$name"
    if (Test-Path $fallback) { return $fallback }
    return $null
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
# Run a test executable with a timeout, returning output lines and exit info.
# Async reads are started before WaitForExit to prevent pipe-buffer deadlock.
# ---------------------------------------------------------------------------
function Invoke-TestExe([string]$Exe, [string]$Filter, [int]$TimeoutSeconds,
                        [string]$TtdExe = '', [string]$TtdOutDir = '',
                        [string]$JsonResultsPath = '',
                        [string]$CdbExe = '', [string]$CdbScript = '',
                        [string[]]$CdbExtraArgs = @()) {
    if ($TtdExe) {
        $psi = [System.Diagnostics.ProcessStartInfo]::new($TtdExe)
        # -launch must be the last TTD option; ArgumentList handles quoting for
        # paths that contain spaces.
        # TTD does not pipe the child's stdout through its own stdout, so GTest
        # output is captured via --gtest_output=json instead.
        $ttdArgs = [System.Collections.Generic.List[string]]::new()
        $ttdArgs.AddRange([string[]]@('-noUI', '-children', '-replayCpuSupport',
                                      'IntelAvx2Required', '-passThroughExit',
                                      '-out', $TtdOutDir, '-launch', $Exe,
                                      "--gtest_filter=$Filter"))
        if ($JsonResultsPath) { $ttdArgs.Add("--gtest_output=json:$JsonResultsPath") }
        foreach ($arg in $ttdArgs) { $psi.ArgumentList.Add($arg) }
    } elseif ($CdbExe) {
        $psi = [System.Diagnostics.ProcessStartInfo]::new($CdbExe)
        # -g:  skip initial loader breakpoint (start running immediately).
        # -G:  skip final exit breakpoint (exit CDB when debuggee exits).
        # -cf: run commands from the user-supplied script on attach.
        # Debuggee path and its arguments follow the CDB options directly;
        # ArgumentList handles quoting for paths that contain spaces.
        $cdbArgs = [System.Collections.Generic.List[string]]::new()
        $cdbArgs.AddRange([string[]]@('-g', '-G', '-cf', $CdbScript))
        foreach ($a in $CdbExtraArgs) { $cdbArgs.Add($a) }
        $cdbArgs.AddRange([string[]]@($Exe, "--gtest_filter=$Filter"))
        if ($JsonResultsPath) { $cdbArgs.Add("--gtest_output=json:$JsonResultsPath") }
        foreach ($arg in $cdbArgs) { $psi.ArgumentList.Add($arg) }
    } else {
        $psi = [System.Diagnostics.ProcessStartInfo]::new($Exe, "--gtest_filter=$Filter")
    }
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow         = $true

    $queue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
    $proc  = [System.Diagnostics.Process]::Start($psi)

    # Lines from stdout and stderr are interleaved in arrival order.  Ordering is
    # line-granular, not byte-exact, because each stream is read independently.
    # Once a stable PowerShell ships on .NET 11+, use ProcessStartInfo.StandardOutputHandle
    # and StandardErrorHandle to point both streams at the same pipe write-end for
    # true byte-exact ordering.
    $outTask = [MhookStreamInterleaver]::Drain($proc.StandardOutput, $queue)
    $errTask = [MhookStreamInterleaver]::Drain($proc.StandardError, $queue)

    $finished = $proc.WaitForExit($TimeoutSeconds * 1000)
    if (-not $finished) {
        $proc.Kill($true)   # kills process tree (PS 7+ / .NET 5+)
    }
    # Wait for both drain tasks to finish (pipes EOF when process exits/is killed).
    [System.Threading.Tasks.Task]::WhenAll($outTask, $errTask).GetAwaiter().GetResult()

    return [pscustomobject]@{
        Lines    = [string[]]$queue.ToArray()
        ExitCode = if ($finished) { $proc.ExitCode } else { -1 }
        TimedOut = -not $finished
    }
}

# ---------------------------------------------------------------------------
# Run one (config, iteration): build status, run the exe, parse counts, write
# the log.  Returns a result object — no Write-Host / exit, so it is safe to
# call from a ForEach-Object -Parallel runspace.  A TTD/CDB infrastructure
# failure is reported via the InfraError field (the caller decides how to react).
# ---------------------------------------------------------------------------
function Invoke-OneRun {
    param(
        [pscustomobject]$Cfg,
        [int]$Iter,
        [string]$IterDir,
        [string]$TestExe,
        [string]$Filter,
        [int]$TimeoutSeconds,
        [switch]$NoBuild,
        [string]$TtdExe,
        [string]$Cdb,
        [string]$CdbX64Exe,
        [string]$CdbX86Exe,
        [string[]]$CdbArgs
    )

    $buildStatus = if ($NoBuild)                { 'SKIP' }
                   elseif (Test-Path $TestExe)  { 'OK'   }
                   else                         { 'FAILED' }

    $testStatus = $null; $testDetail = $null; $failLines = @(); $infraError = $null

    if ($buildStatus -in 'OK', 'SKIP') {
        if (-not (Test-Path $TestExe)) {
            $testStatus = 'NO EXE'
        } else {
            # Under TTD/CDB the GTest results go to a JSON file (TTD does not pipe the
            # child's stdout; CDB mixes its own output in), keeping pass/fail counting clean.
            $cdbForConfig = if ($Cdb) {
                if ($Cfg.OutArch -eq 'x64') { $CdbX64Exe } else { $CdbX86Exe }
            } else { '' }

            $jsonPath = if ($TtdExe -or $cdbForConfig) {
                Join-Path $IterDir "$($Cfg.OutArch)-$($Cfg.MSBuildConfig).json"
            } else { '' }

            $run = Invoke-TestExe -Exe $TestExe -Filter $Filter -TimeoutSeconds $TimeoutSeconds `
                                  -TtdExe $TtdExe -TtdOutDir $IterDir -JsonResultsPath $jsonPath `
                                  -CdbExe $cdbForConfig -CdbScript $Cdb -CdbExtraArgs $CdbArgs

            # Runner-itself failure (TTD/CDB): non-zero exit and no JSON written.
            if (($TtdExe -or $cdbForConfig) -and $run.ExitCode -ne 0 -and -not (Test-Path $jsonPath)) {
                $errLine = $run.Lines | Where-Object { $_ -match '^Error:' } | Select-Object -First 1
                $infraError = if ($TtdExe) {
                    "TTD failed to record for $($Cfg.MSBuildConfig)|$($Cfg.OutArch) (exit $($run.ExitCode))$(if ($errLine) { ': ' + $errLine }). TTD requires an elevated session."
                } else {
                    "CDB failed for $($Cfg.MSBuildConfig)|$($Cfg.OutArch) (exit $($run.ExitCode))$(if ($errLine) { ': ' + $errLine })."
                }
            }

            $ok = -not $run.TimedOut -and $run.ExitCode -eq 0

            $counts = $null
            if ($jsonPath -and (Test-Path $jsonPath)) {
                try {
                    $j       = Get-Content $jsonPath -Raw | ConvertFrom-Json
                    $nFailed = [int]$j.failures + [int]$j.errors
                    $counts  = @{ Passed = [int]$j.tests - $nFailed; Failed = $nFailed }
                    foreach ($suite in $j.testsuites) {
                        foreach ($tc in $suite.testcases) {
                            if ($tc.result -eq 'FAILED') {
                                $failLines += "[  FAILED  ] $($suite.name).$($tc.name)"
                            }
                        }
                    }
                    # JSON is authoritative (TTD's -passThroughExit is always 0; CDB's exit varies).
                    $ok = -not $run.TimedOut -and $nFailed -eq 0
                } catch {}
            }
            if (-not $counts) {
                $counts    = Get-GtestCounts $run.Lines
                $failLines = @($run.Lines | Where-Object { $_ -match '^\[  FAILED  \]' })
            }
            $total = $counts.Passed + $counts.Failed

            $logFile = Join-Path $IterDir "$($Cfg.OutArch)-$($Cfg.MSBuildConfig).log"
            $run.Lines | Set-Content -Path $logFile -Encoding UTF8

            if ($run.TimedOut)  { $testStatus = 'TIMEOUT' }
            elseif ($ok)        { $testStatus = 'PASS'; $testDetail = "$($counts.Passed)/$total" }
            else                { $testStatus = 'FAIL'; $testDetail = "$($counts.Passed)/$total" }
        }
    } else {
        $testStatus = '-'
    }

    return [pscustomobject]@{
        Iter       = $Iter
        Arch       = $Cfg.OutArch
        Config     = $Cfg.MSBuildConfig
        Build      = $buildStatus
        TestStatus = $testStatus
        TestDetail = $testDetail
        FailLines  = $failLines
        InfraError = $infraError
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
$sln    = Join-Path $SolutionDir 'libmhook.slnx'
if (-not (Test-Path $sln)) { Write-Error "Solution not found: $sln"; exit 1 }

$runDir = Join-Path $ResultsDir (Get-Date -Format 'yyyy-MM-ddTHHmmss')
$null   = New-Item -ItemType Directory -Path $runDir -Force

if ($Trace -and $Cdb) {
    Write-Error '-Trace and -Cdb cannot be used together.'
    exit 1
}
if ($CdbArgs.Count -gt 0 -and -not $Cdb) {
    Write-Error '-CdbArgs requires -Cdb.'
    exit 1
}

$ttdExe = $null
if ($Trace) {
    $ttdExe = Find-Ttd
    if (-not $ttdExe) {
        Write-Error 'ttd.exe not found on PATH or in %LOCALAPPDATA%\Microsoft\WindowsApps\. Install WinDbg or the Windows SDK to get TTD.'
        exit 1
    }
    Write-Host "TTD      : $ttdExe"
}

$cdbX64Exe = $null; $cdbX86Exe = $null
if ($Cdb) {
    if (-not (Test-Path $Cdb)) {
        Write-Error "CDB script not found: $Cdb"
        exit 1
    }
    if ($configs | Where-Object { $_.OutArch -eq 'x64' }) {
        $cdbX64Exe = Find-Cdb 'x64'
        if (-not $cdbX64Exe) {
            Write-Error 'cdbX64.exe not found on PATH or in %LOCALAPPDATA%\Microsoft\WindowsApps\.'
            exit 1
        }
        Write-Host "CDB x64  : $cdbX64Exe"
    }
    if ($configs | Where-Object { $_.OutArch -eq 'Win32' }) {
        $cdbX86Exe = Find-Cdb 'Win32'
        if (-not $cdbX86Exe) {
            Write-Error 'cdbX86.exe not found on PATH or in %LOCALAPPDATA%\Microsoft\WindowsApps\.'
            exit 1
        }
        Write-Host "CDB x86  : $cdbX86Exe"
    }
}

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

$padWidth        = $Repeat.ToString().Length
$allIterResults  = @()
$totalWork       = $Repeat * $configs.Count

# Iteration subfolder: the run dir itself when Repeat == 1, else a zero-padded
# per-iteration subfolder so passing iterations can be cleaned up independently.
function Get-IterDir([int]$Iter) {
    if ($Repeat -eq 1) { $runDir }
    else { Join-Path $runDir $Iter.ToString().PadLeft($padWidth, '0') }
}

if ($Parallel -le 1) {
    # =======================================================================
    # Sequential (default) — per-iteration headers + live "Testing ... PASS" lines.
    # =======================================================================
    $cfgNum    = 0
    $stopEarly = $false

    for ($iter = 1; $iter -le $Repeat; $iter++) {
        $iterDir = Get-IterDir $iter
        if ($Repeat -gt 1) {
            $null = New-Item -ItemType Directory -Path $iterDir -Force
            Write-Host "--- Iteration $iter/$Repeat ---"
        }

        $iterResults = @()

        foreach ($cfg in $configs) {
            $label   = "$($cfg.MSBuildConfig)|$($cfg.OutArch)"
            $testExe = Join-Path $SolutionDir "build" "artifacts" "mhook-unit-tests" $cfg.OutDir "mhook-unit-tests.exe"

            $cfgNum++
            $pct    = [int]($cfgNum / $totalWork * 100)
            $status = if ($Repeat -gt 1) { "Iteration $iter/$Repeat  —  $label" } else { $label }
            Write-Progress -Activity 'run-tests.ps1' -Status $status -PercentComplete $pct

            if (Test-Path $testExe) { Write-Host "  Testing  $label ..." -NoNewline }

            $r = Invoke-OneRun -Cfg $cfg -Iter $iter -IterDir $iterDir -TestExe $testExe `
                               -Filter $Filter -TimeoutSeconds $TimeoutSeconds -NoBuild:$NoBuild `
                               -TtdExe $ttdExe -Cdb $Cdb -CdbX64Exe $cdbX64Exe -CdbX86Exe $cdbX86Exe -CdbArgs $CdbArgs

            if ($r.InfraError) { Write-Host ''; Write-Error $r.InfraError; exit 1 }

            switch ($r.TestStatus) {
                'TIMEOUT' { Write-Host " TIMEOUT (>${TimeoutSeconds}s)" -ForegroundColor Yellow }
                'PASS'    { Write-Host " PASS ($($r.TestDetail))" }
                'FAIL'    { Write-Host " FAIL ($($r.TestDetail))"
                            $r.FailLines | Select-Object -First 10 | ForEach-Object { Write-Host "    $_" } }
            }

            $iterResults += $r

            if ($StopOnFailure -and $r.TestStatus -in 'FAIL', 'TIMEOUT') {
                Write-Host "  Stopping after first failure (-StopOnFailure)." -ForegroundColor Yellow
                $stopEarly = $true
                break
            }
        }

        $allIterResults += $iterResults

        # Clean up this iteration's subfolder immediately if everything passed.
        $iterOk = -not ($iterResults | Where-Object { $_.TestStatus -ne 'PASS' })
        if ($Repeat -gt 1 -and $iterOk -and -not $KeepResults) {
            $ProgressPreference = 'SilentlyContinue'
            Remove-Item -Recurse -Force $iterDir
            $ProgressPreference = 'Continue'
        }

        if ($Repeat -gt 1) { Write-Host '' }
        if ($stopEarly) { break }
    }

    Write-Progress -Activity 'run-tests.ps1' -Completed
} else {
    # =======================================================================
    # Parallel — dispatch the flat (iteration x config) work list through a
    # runspace pool (-ThrottleLimit $Parallel).
    # =======================================================================
    $work = foreach ($iter in 1..$Repeat) {
        $iterDir = Get-IterDir $iter
        $null = New-Item -ItemType Directory -Path $iterDir -Force
        foreach ($cfg in $configs) {
            [pscustomobject]@{
                Iter    = $iter
                IterDir = $iterDir
                Cfg     = $cfg
                TestExe = Join-Path $SolutionDir "build" "artifacts" "mhook-unit-tests" $cfg.OutDir "mhook-unit-tests.exe"
            }
        }
    }

    # ForEach-Object -Parallel runspaces don't inherit script functions, so pass
    # their bodies in via $using: and re-create them.  The MhookStreamInterleaver
    # type is AppDomain-global (Add-Type) and already visible to child runspaces.
    $stopFlag         = [hashtable]::Synchronized(@{ stop = $false })
    $invokeOneRunDef  = (Get-Item function:Invoke-OneRun).ScriptBlock.ToString()
    $invokeTestExeDef = (Get-Item function:Invoke-TestExe).ScriptBlock.ToString()
    $getCountsDef     = (Get-Item function:Get-GtestCounts).ScriptBlock.ToString()

    $prog      = @{ runs = 0; iters = 0 }   # reference type → mutations persist across the consumer scope
    $iterTally = @{}
    $nConfigs  = $configs.Count

    $allIterResults = $work | ForEach-Object -ThrottleLimit $Parallel -Parallel {
        $job  = $_
        $flag = $using:stopFlag

        ${function:Invoke-TestExe}  = [scriptblock]::Create($using:invokeTestExeDef)
        ${function:Get-GtestCounts} = [scriptblock]::Create($using:getCountsDef)
        ${function:Invoke-OneRun}   = [scriptblock]::Create($using:invokeOneRunDef)

        # Best-effort -StopOnFailure: a queued job started after a failure skips fast.
        if (($using:StopOnFailure) -and $flag.stop) {
            return [pscustomobject]@{
                Iter = $job.Iter; Arch = $job.Cfg.OutArch; Config = $job.Cfg.MSBuildConfig
                Build = 'SKIP'; TestStatus = 'SKIP'; TestDetail = $null; FailLines = @(); InfraError = $null
            }
        }

        $r = Invoke-OneRun -Cfg $job.Cfg -Iter $job.Iter -IterDir $job.IterDir -TestExe $job.TestExe `
                           -Filter $using:Filter -TimeoutSeconds $using:TimeoutSeconds -NoBuild:$using:NoBuild `
                           -TtdExe $using:ttdExe -Cdb $using:Cdb -CdbX64Exe $using:cdbX64Exe `
                           -CdbX86Exe $using:cdbX86Exe -CdbArgs $using:CdbArgs

        if (($using:StopOnFailure) -and ($r.InfraError -or $r.TestStatus -in 'FAIL', 'TIMEOUT')) {
            $flag.stop = $true
        }
        $r
    } | ForEach-Object {
        # Main-thread consumer: print each completion and keep the progress bar live.
        $r = $_
        $prog.runs++
        if (-not $iterTally.ContainsKey($r.Iter)) { $iterTally[$r.Iter] = 0 }
        $iterTally[$r.Iter]++
        if ($iterTally[$r.Iter] -eq $nConfigs) { $prog.iters++ }

        $label = "$($r.Config)|$($r.Arch)"
        $tag   = if ($Repeat -gt 1) { "[iter $($r.Iter.ToString().PadLeft($padWidth, '0'))]  " } else { '' }
        switch ($r.TestStatus) {
            'TIMEOUT' { Write-Host "  $tag$label  TIMEOUT (>${TimeoutSeconds}s)" -ForegroundColor Yellow }
            'PASS'    { Write-Host "  $tag$label  PASS ($($r.TestDetail))" }
            'FAIL'    { Write-Host "  $tag$label  FAIL ($($r.TestDetail))" -ForegroundColor Red
                        $r.FailLines | Select-Object -First 10 | ForEach-Object { Write-Host "    $_" } }
            'NO EXE'  { Write-Host "  $tag$label  NO EXE" -ForegroundColor Red }
        }
        if ($r.InfraError) { Write-Error $r.InfraError }

        Write-Progress -Activity 'run-tests.ps1' `
            -Status "Completed $($prog.iters)/$Repeat iterations ($($prog.runs)/$totalWork runs)" `
            -PercentComplete ([int]($prog.runs / $totalWork * 100))
        $r
    }

    Write-Progress -Activity 'run-tests.ps1' -Completed

    # End-of-run cleanup: drop each iteration's folder if none of its runs failed.
    if ($Repeat -gt 1 -and -not $KeepResults) {
        $ProgressPreference = 'SilentlyContinue'
        foreach ($iter in 1..$Repeat) {
            $rows = @($allIterResults | Where-Object { $_.Iter -eq $iter })
            if (-not ($rows | Where-Object { $_.TestStatus -notin 'PASS', 'SKIP' })) {
                Remove-Item -Recurse -Force (Get-IterDir $iter) -ErrorAction SilentlyContinue
            }
        }
        $ProgressPreference = 'Continue'
    }
}

# ---------------------------------------------------------------------------
# Aggregate results across all iterations (one row per config)
# ---------------------------------------------------------------------------
$results = foreach ($cfg in $configs) {
    $rows = @($allIterResults | Where-Object { $_.Arch -eq $cfg.OutArch -and $_.Config -eq $cfg.MSBuildConfig })
    if ($rows.Count -eq 0) { continue }

    $worst = if ($rows | Where-Object { $_.TestStatus -eq 'TIMEOUT' }) { 'TIMEOUT' }
             elseif ($rows | Where-Object { $_.TestStatus -eq 'FAIL' }) { 'FAIL'    }
             elseif ($rows | Where-Object { $_.TestStatus -eq 'PASS' }) { 'PASS'    }
             else { ($rows | Select-Object -First 1).TestStatus }

    $worstDetail = ($rows | Where-Object { $_.TestStatus -eq $worst } | Select-Object -First 1).TestDetail
    $passingRuns = @($rows | Where-Object { $_.TestStatus -eq 'PASS' }).Count

    [pscustomobject]@{
        Arch        = $cfg.OutArch
        Config      = $cfg.MSBuildConfig
        Build       = ($rows | Select-Object -First 1).Build
        TestStatus  = $worst
        TestDetail  = $worstDetail
        PassingRuns = $passingRuns
    }
}

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------
Write-Host '=== Summary ==='
Write-Host ''

$archWidth   = ($results | ForEach-Object { $_.Arch.Length }       | Measure-Object -Max).Maximum
$configWidth = ($results | ForEach-Object { $_.Config.Length }     | Measure-Object -Max).Maximum
$buildWidth  = 6
$testWidth   = ($results | ForEach-Object { $_.TestStatus.Length } | Measure-Object -Max).Maximum
$detailWidth = 7

if ($Repeat -gt 1) {
    $runsLabel = "Runs"
    $runsWidth = [Math]::Max($runsLabel.Length, "$Repeat/$Repeat".Length)

    $header = "  {0,-$archWidth}  {1,-$configWidth}  {2,-$buildWidth}  {3,-$testWidth}  {4,-$detailWidth}  {5,-$runsWidth}" `
        -f 'Arch', 'Config', 'Build', 'Tests', 'Pass/N', $runsLabel
    $sep    = "  {0}  {1}  {2}  {3}  {4}  {5}" `
        -f ('-' * $archWidth), ('-' * $configWidth), ('-' * $buildWidth), ('-' * $testWidth), ('-' * $detailWidth), ('-' * $runsWidth)
} else {
    $header = "  {0,-$archWidth}  {1,-$configWidth}  {2,-$buildWidth}  {3,-$testWidth}  {4,-$detailWidth}" `
        -f 'Arch', 'Config', 'Build', 'Tests', 'Pass/N'
    $sep    = "  {0}  {1}  {2}  {3}  {4}" `
        -f ('-' * $archWidth), ('-' * $configWidth), ('-' * $buildWidth), ('-' * $testWidth), ('-' * $detailWidth)
}

Write-Host $header
Write-Host $sep

foreach ($r in $results) {
    $detailCol = if ($r.TestDetail) { $r.TestDetail } else { '' }

    if ($Repeat -gt 1) {
        $runsCol = "$($r.PassingRuns)/$Repeat"
        $line    = "  {0,-$archWidth}  {1,-$configWidth}  {2,-$buildWidth}  {3,-$testWidth}  {4,-$detailWidth}  {5,-$runsWidth}" `
            -f $r.Arch, $r.Config, $r.Build, $r.TestStatus, $detailCol, $runsCol
    } else {
        $line    = "  {0,-$archWidth}  {1,-$configWidth}  {2,-$buildWidth}  {3,-$testWidth}  {4,-$detailWidth}" `
            -f $r.Arch, $r.Config, $r.Build, $r.TestStatus, $detailCol
    }

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

if ($allOk -and -not $KeepResults) {
    $ProgressPreference = 'SilentlyContinue'
    Remove-Item -Recurse -Force $runDir
    $ProgressPreference = 'Continue'
} else {
    Write-Host "Results saved to: $runDir"
}

exit ($allOk ? 0 : 1)
