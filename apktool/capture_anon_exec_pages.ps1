param(
    [string]$Serial = "8022cd7",
    [string]$Package = "com.aniplex.nananiji.ps",
    [string]$Activity = "com.tomatolib.LibMainActivity",
    [string]$RunLabel = "anon-exec-pages",
    [int]$DurationSec = 205,
    [string]$CaptureAtSec = "145,155"
)

$ErrorActionPreference = "Stop"
$adb = if ($env:NANAON_ADB) { $env:NANAON_ADB } else { '<ANDROID_SDK>\platform-tools\adb.exe>' }
$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$out = Join-Path $root ("tools\_tmp\trace-{0}-{1}" -f $Package, $RunLabel)
New-Item -ItemType Directory -Force -Path $out | Out-Null

function Invoke-Adb {
    param([string[]]$AdbArgs)
    & $adb -s $Serial @AdbArgs
}

function Invoke-AdbText {
    param([string[]]$AdbArgs)
    $value = Invoke-Adb $AdbArgs 2>&1
    return (($value | ForEach-Object { $_.ToString() }) -join "`n")
}

function Save-AdbText {
    param([string[]]$AdbArgs, [string]$Path)
    Invoke-AdbText $AdbArgs | Set-Content -LiteralPath $Path -Encoding utf8
}

function Save-AdbBinary {
    param([string[]]$AdbArgs, [string]$Path)
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $adb
    $psi.Arguments = "-s $Serial " + ($AdbArgs -join " ")
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $psi
    [void]$process.Start()
    $file = [IO.File]::Open($Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $process.StandardOutput.BaseStream.CopyTo($file) }
    finally { $file.Dispose() }
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        if ($stderr) { Set-Content -LiteralPath "$Path.err.txt" -Value $stderr -Encoding utf8 }
        throw "binary adb command failed ($($process.ExitCode)): $($AdbArgs -join ' ')"
    }
}

function Save-Screenshot {
    param([string]$Path)
    Save-AdbBinary @("exec-out", "screencap", "-p") $Path
}

function Capture-AnonExecutablePages {
    param([int]$Elapsed, [string]$MainPid)
    $maps = Invoke-AdbText @("shell", "cat", "/proc/$MainPid/maps")
    $mapsPath = Join-Path $out ("maps-anon-rxp-{0:D3}s.txt" -f $Elapsed)
    Set-Content -LiteralPath $mapsPath -Value $maps -Encoding utf8

    # Only anonymous r-xp ranges are read.  Skip large ranges to avoid the
    # Unity disruption observed in the earlier broad /proc/<pid>/mem dump.
    $ranges = @(
        $maps -split "`r?`n" |
            ForEach-Object {
                if ($_ -match '^([0-9a-f]+)-([0-9a-f]+)\s+r-xp\s+00000000\s+00:00\s+0\s*$') {
                    $start = [Convert]::ToUInt64($Matches[1], 16)
                    $end = [Convert]::ToUInt64($Matches[2], 16)
                    $size = $end - $start
                    if ($size -gt 0 -and $size -le 0x20000) {
                        [pscustomobject]@{ Start = $start; End = $end; Size = $size }
                    }
                }
            }
    )
    $index = 0
    foreach ($range in $ranges) {
        $skip = [uint64]($range.Start / 0x1000)
        $count = [int](($range.Size + 0xfff) / 0x1000)
        $name = "anon-rxp-{0:D3}s-{1:D2}-0x{2:x}-0x{3:x}.bin" -f $Elapsed, $index, $range.Start, $range.End
        $file = Join-Path $out $name
        Save-AdbBinary @(
            "exec-out", "dd", "if=/proc/$MainPid/mem", "bs=4096",
            "skip=$skip", "count=$count", "status=none"
        ) $file
        $index++
    }
    Add-Content -LiteralPath (Join-Path $out "meta.txt") -Value (
        "anon_r-xp_capture_elapsed={0}s ranges={1}" -f $Elapsed, $index
    )
}

$captureTimes = @(
    [regex]::Matches($CaptureAtSec, '\d+') |
        ForEach-Object { [int]$_.Value } |
        Select-Object -Unique
)
$trace = "/sys/kernel/tracing"
Save-AdbText @(
    "shell", "sh", "-c",
    "echo -n tracing_on=; cat $trace/tracing_on; echo -n events=; grep -h '^signal_generate\|^sched_process_fork' $trace/set_event 2>/dev/null || true"
) (Join-Path $out "trace-state-before.txt")
Invoke-Adb @(
    "shell", "sh", "-c",
    "echo 0 > $trace/tracing_on; echo nop > $trace/current_tracer; echo > $trace/trace; echo 1 > $trace/events/signal/signal_generate/enable; echo 1 > $trace/events/sched/sched_process_fork/enable; echo 1 > $trace/tracing_on"
) | Out-Null

Save-AdbText @("shell", "getprop", "ro.product.model") (Join-Path $out "device-model.txt")
Save-AdbText @("shell", "getprop", "ro.product.device") (Join-Path $out "device-name.txt")
Save-AdbText @("shell", "getprop", "ro.build.version.release") (Join-Path $out "device-android.txt")
Save-AdbText @("shell", "getprop", "ro.build.version.sdk") (Join-Path $out "device-sdk.txt")
Save-AdbText @("shell", "id") (Join-Path $out "device-id.txt")
Save-AdbText @("shell", "getenforce") (Join-Path $out "device-selinux.txt")

if ((Invoke-AdbText @("get-state")).Trim() -ne "device") {
    throw "whitelisted device $Serial is not online"
}

Invoke-Adb @("shell", "am", "force-stop", $Package) | Out-Null
$started = Get-Date
$runClock = [Diagnostics.Stopwatch]::StartNew()
Save-AdbText @("shell", "am", "start", "-n", "$Package/$Activity") (Join-Path $out "am-start.txt")

$mainPid = $null
for ($i = 0; $i -lt 20 -and -not $mainPid; $i++) {
    $candidate = (Invoke-AdbText @("shell", "pidof", $Package)).Trim()
    if ($candidate) { $mainPid = ($candidate -split '\s+')[0] }
    if (-not $mainPid) { Start-Sleep -Milliseconds 500 }
}
if (-not $mainPid) { throw "main process not found for $Package" }

Set-Content -LiteralPath (Join-Path $out "meta.txt") -Value @(
    "started_at=$($started.ToString('o'))"
    "serial=$Serial"
    "package=$Package"
    "main_pid=$mainPid"
    "duration_sec=$DurationSec"
    "capture_at_sec=$($captureTimes -join ',')"
) -Encoding utf8

try {
    $snapshotTimes = @(0, 8, 30, 60, 120, 150, 180, 190)
    $capturedSnapshots = @{}
    $capturedPages = @{}
    $lastReported = -1
    while ($runClock.Elapsed.TotalSeconds -le $DurationSec) {
        # ADB polling and screenshot capture can take longer than one second;
        # use the monotonic clock instead of loop iterations for all timings.
        $elapsed = [int][Math]::Floor($runClock.Elapsed.TotalSeconds)
        Invoke-Adb @("shell", "kill", "-0", $mainPid) | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Add-Content -LiteralPath (Join-Path $out "meta.txt") -Value (
                "main_pid_gone_elapsed_sec={0:N3}" -f $runClock.Elapsed.TotalSeconds
            )
            break
        }
        foreach ($target in $snapshotTimes) {
            if ($elapsed -ge $target -and -not $capturedSnapshots.ContainsKey($target)) {
                $stamp = "{0:D3}s" -f $target
                Save-AdbText @("shell", "ps", "-T", "-p", $mainPid) (Join-Path $out "tasks-$stamp.txt")
                Save-AdbText @("shell", "cat", "/proc/$mainPid/maps") (Join-Path $out "maps-$stamp.txt")
                if ($target -in @(8, 30, 150, 180, 190)) {
                    Save-Screenshot (Join-Path $out "screen-$stamp.png")
                }
                $capturedSnapshots[$target] = $true
            }
        }
        foreach ($target in $captureTimes) {
            if ($elapsed -ge $target -and -not $capturedPages.ContainsKey($target)) {
                Capture-AnonExecutablePages -Elapsed $target -MainPid $mainPid
                Add-Content -LiteralPath (Join-Path $out "meta.txt") -Value (
                    "anon_capture_{0}s_actual_elapsed_sec={1:N3}" -f $target, $runClock.Elapsed.TotalSeconds
                )
                $capturedPages[$target] = $true
            }
        }
        if ($elapsed -ne $lastReported -and $elapsed % 30 -eq 0) {
            Write-Output "elapsed=${elapsed}s pid=$mainPid"
            $lastReported = $elapsed
        }
        Start-Sleep -Milliseconds 500
    }
}
finally {
    Save-AdbText @("shell", "cat", "$trace/trace") (Join-Path $out "ftrace-final.txt")
    Save-AdbText @("shell", "cat", "$trace/tracing_on") (Join-Path $out "tracing-on-final.txt")
    Invoke-Adb @(
        "shell", "sh", "-c",
        "echo 0 > $trace/tracing_on; echo 0 > $trace/events/signal/signal_generate/enable; echo 0 > $trace/events/sched/sched_process_fork/enable; echo > $trace/trace"
    ) | Out-Null
    Invoke-Adb @("shell", "dumpsys", "activity", "exit-info", $Package) |
        Set-Content -LiteralPath (Join-Path $out "exit-info.txt") -Encoding utf8
    Save-AdbText @("shell", "logcat", "-d", "-v", "threadtime") (Join-Path $out "logcat-final.txt")
    Invoke-Adb @("shell", "am", "force-stop", $Package) | Out-Null
    Add-Content -LiteralPath (Join-Path $out "meta.txt") -Value "finished_at=$((Get-Date).ToString('o'))"
}

Write-Output "captured anonymous executable pages for $Package pid=$mainPid into $out"
