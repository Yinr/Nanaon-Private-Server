param(
    [string]$Serial = "8022cd7",
    [string]$Package = "com.aniplex.nananiji.ps",
    [string]$Activity = "com.tomatolib.LibMainActivity",
    [string]$RunLabel = "thread2-live",
    [int]$DurationSec = 205,
    [int]$SnapshotEverySec = 1,
    [switch]$CaptureRuntime
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

function Save-Screenshot {
    param([string]$Path)
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $adb
    $psi.Arguments = "-s $Serial exec-out screencap -p"
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $psi
    [void]$process.Start()
    $file = [IO.File]::Open($Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $process.StandardOutput.BaseStream.CopyTo($file) }
    finally { $file.Dispose() }
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) { throw "screencap failed with exit code $($process.ExitCode)" }
}

function Dump-LibraryRange {
    param([int]$Elapsed)
    $maps = Invoke-AdbText @("shell", "cat", "/proc/$mainPid/maps")
    $match = [regex]::Match(
        $maps,
        '(?m)^([0-9a-f]+)-[0-9a-f]+\s+r-xp\s+00000000\b[^\r\n]*libcompatible\.so'
    )
    if (-not $match.Success) {
        Add-Content -LiteralPath (Join-Path $out "meta.txt") -Value "runtime_dump_elapsed=${Elapsed}s base=NOT_FOUND"
        return
    }
    $base = [Convert]::ToUInt64($match.Groups[1].Value, 16)
    Add-Content -LiteralPath (Join-Path $out "meta.txt") -Value ("runtime_dump_elapsed={0}s base=0x{1:x}" -f $Elapsed, $base)
    $ranges = @(
        @{ Name = "asm-kill"; Offset = [uint64]0xcdd00; Size = 0x3000 },
        @{ Name = "code-3e"; Offset = [uint64]0x3d000; Size = 0x6000 },
        @{ Name = "code-43"; Offset = [uint64]0x44000; Size = 0x6000 },
        @{ Name = "code-116"; Offset = [uint64]0x116000; Size = 0x4000 }
    )
    foreach ($range in $ranges) {
        $address = $base + $range.Offset
        $page = $address - ($address % 0x1000)
        $skip = [uint64]($page / 0x1000)
        $count = [int]($range.Size / 0x1000)
        $file = Join-Path $out ("libcompatible-{0}-{1:x}.bin" -f $Elapsed, $range.Offset)
        $errFile = Join-Path $out ("libcompatible-{0}-{1:x}.err.txt" -f $Elapsed, $range.Offset)
        & $adb -s $Serial exec-out dd "if=/proc/$mainPid/mem" "bs=4096" "skip=$skip" "count=$count" "status=none" > $file 2> $errFile
        if ($LASTEXITCODE -ne 0) {
            Add-Content -LiteralPath (Join-Path $out "meta.txt") -Value ("runtime_dump_failed_elapsed={0}s range={1} exit={2}" -f $Elapsed, $range.Name, $LASTEXITCODE)
        } else {
            Add-Content -LiteralPath (Join-Path $out "meta.txt") -Value ("runtime_dump_ok_elapsed={0}s range={1} file={2}" -f $Elapsed, $range.Name, (Split-Path $file -Leaf))
        }
    }
}

function Trace-Write {
    param([string]$Command)
    Invoke-Adb @("shell", $Command) | Out-Null
}

$trace = "/sys/kernel/tracing"
$traceBackup = Join-Path $out "trace-state-before.txt"
Save-AdbText @("shell", "sh", "-c", "echo -n tracing_on=; cat $trace/tracing_on; echo -n events=; grep -h '^signal_generate\|^sched_process_fork' $trace/set_event 2>/dev/null || true") $traceBackup

Save-AdbText @("shell", "getprop", "ro.product.model") (Join-Path $out "device-model.txt")
Save-AdbText @("shell", "getprop", "ro.product.name") (Join-Path $out "device-name.txt")
Save-AdbText @("shell", "getprop", "ro.build.version.release") (Join-Path $out "device-android.txt")
Save-AdbText @("shell", "getprop", "ro.build.version.sdk") (Join-Path $out "device-sdk.txt")
Save-AdbText @("shell", "id") (Join-Path $out "device-id.txt")
Save-AdbText @("shell", "getenforce") (Join-Path $out "device-selinux.txt")

Invoke-Adb @("shell", "am", "force-stop", $Package) | Out-Null
Trace-Write "echo 0 > $trace/tracing_on; echo nop > $trace/current_tracer; echo > $trace/trace; echo 1 > $trace/events/signal/signal_generate/enable; echo 1 > $trace/events/sched/sched_process_fork/enable; echo 1 > $trace/tracing_on"
$started = Get-Date
Save-AdbText @("shell", "am", "start", "-n", "$Package/$Activity") (Join-Path $out "am-start.txt")

$mainPid = $null
for ($i = 0; $i -lt 20 -and -not $mainPid; $i++) {
    $candidate = (Invoke-AdbText @("shell", "pidof", $Package)).Trim()
    if ($candidate) { $mainPid = ($candidate -split '\s+')[0] }
    if (-not $mainPid) { Start-Sleep -Milliseconds 500 }
}
if (-not $mainPid) {
    Trace-Write "echo 0 > $trace/tracing_on; echo 0 > $trace/events/signal/signal_generate/enable; echo 0 > $trace/events/sched/sched_process_fork/enable"
    throw "main process not found for $Package"
}

Set-Content -LiteralPath (Join-Path $out "meta.txt") -Value @(
    "started_at=$($started.ToString('o'))"
    "serial=$Serial"
    "package=$Package"
    "main_pid=$mainPid"
    "duration_sec=$DurationSec"
) -Encoding utf8

$seenThread2 = @{}
$nextSnapshot = 0
try {
    for ($elapsed = 0; $elapsed -le $DurationSec; $elapsed += $SnapshotEverySec) {
        Invoke-Adb @("shell", "kill", "-0", $mainPid) | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Add-Content -LiteralPath (Join-Path $out "meta.txt") -Value "main_pid_gone_elapsed=$elapsed"
            break
        }

        $threadTable = Invoke-AdbText @("shell", "ps", "-T", "-p", $mainPid)
        $tids = @(
            $threadTable -split "`r?`n" |
                ForEach-Object {
                    if ($_ -match '^\s*\S+\s+\d+\s+(\d+)\s+.*\sThread-2\s*$') { $Matches[1] }
                } |
                Where-Object { $_ -match '^\d+$' } |
                Select-Object -Unique
        )
        if ($tids.Count -gt 0) {
            Add-Content -LiteralPath (Join-Path $out "meta.txt") -Value "scan_elapsed=${elapsed}s thread2_candidates=$($tids -join ',')"
        }
        foreach ($tid in $tids) {
            if (-not $seenThread2.ContainsKey($tid)) {
                $seenThread2[$tid] = $elapsed
                $dir = Join-Path $out ("thread2-{0}" -f $tid)
                New-Item -ItemType Directory -Force -Path $dir | Out-Null
                Save-AdbText @("shell", "cat", "/proc/$mainPid/task/$tid/status") (Join-Path $dir "status-first.txt")
                Save-AdbText @("shell", "cat", "/proc/$mainPid/task/$tid/syscall") (Join-Path $dir "syscall-first.txt")
                Save-AdbText @("shell", "cat", "/proc/$mainPid/task/$tid/wchan") (Join-Path $dir "wchan-first.txt")
                Save-AdbText @("shell", "grep", "^PPid:", "/proc/$mainPid/task/$tid/status") (Join-Path $dir "ppid-first.txt")
                Add-Content -LiteralPath (Join-Path $out "meta.txt") -Value "thread2_tid=$tid first_seen_elapsed=${elapsed}s"
            }
        }

        if ($elapsed -eq 0 -or $elapsed -eq 8 -or $elapsed -eq 30 -or $elapsed -eq 60 -or $elapsed -eq 120 -or $elapsed -eq 150 -or ($elapsed -ge 170 -and $elapsed -le 195)) {
            $stamp = "{0:D3}s" -f $elapsed
            Save-AdbText @("shell", "ps", "-T", "-p", $mainPid) (Join-Path $out "tasks-$stamp.txt")
            Save-AdbText @("shell", "cat", "/proc/$mainPid/maps") (Join-Path $out "maps-$stamp.txt")
            Save-AdbText @("shell", "ps", "-A", "-o", "PID,PPID,NAME,WCHAN,ARGS") (Join-Path $out "ps-all-$stamp.txt")
            if ($elapsed -in @(8, 30, 60, 120, 150, 180, 190)) { Save-Screenshot (Join-Path $out "screen-$stamp.png") }
        }
        if ($CaptureRuntime -and $elapsed -in @(145, 155)) {
            Dump-LibraryRange -Elapsed $elapsed
        }
        Start-Sleep -Seconds $SnapshotEverySec
    }
}
finally {
    Save-AdbText @("shell", "cat", "$trace/trace") (Join-Path $out "ftrace-final.txt")
    Save-AdbText @("shell", "cat", "$trace/tracing_on") (Join-Path $out "tracing-on-final.txt")
    Trace-Write "echo 0 > $trace/tracing_on; echo 0 > $trace/events/signal/signal_generate/enable; echo 0 > $trace/events/sched/sched_process_fork/enable; echo > $trace/trace"
    Invoke-Adb @("shell", "dumpsys", "activity", "exit-info", $Package) | Set-Content -LiteralPath (Join-Path $out "exit-info.txt") -Encoding utf8
    Save-AdbText @("shell", "logcat", "-d", "-v", "threadtime") (Join-Path $out "logcat-final.txt")
    Invoke-Adb @("shell", "am", "force-stop", $Package) | Out-Null
    Add-Content -LiteralPath (Join-Path $out "meta.txt") -Value "finished_at=$((Get-Date).ToString('o'))"
}

Write-Output "captured $Package pid=$mainPid into $out"
