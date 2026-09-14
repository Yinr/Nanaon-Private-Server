param(
    [string]$Serial = "8022cd7",
    [string]$Package = "com.aniplex.nananiji.ps",
    [string]$Activity = "com.tomatolib.LibMainActivity",
    [string]$RunLabel = "thread2-perf",
    [int]$DurationSec = 205,
    [int]$PollMilliseconds = 500,
    [int]$PerfDurationSec = 15,
    [switch]$CaptureRuntimePage
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

function Read-UInt64Little {
    param(
        [byte[]]$Bytes,
        [int]$Offset
    )
    if ($Offset -lt 0 -or $Offset + 8 -gt $Bytes.Length) { return $null }
    return [BitConverter]::ToUInt64($Bytes, $Offset)
}

function Strip-TopByte {
    param([UInt64]$Value)
    return ($Value -band [UInt64]0x00FFFFFFFFFFFFFF)
}

function Find-MapForAddress {
    param(
        [string]$Maps,
        [UInt64]$Address
    )
    foreach ($line in ($Maps -split "`r?`n")) {
        if ($line -notmatch '^([0-9a-f]+)-([0-9a-f]+)\s+([^\s]+)\s+([0-9a-f]+)\s+([^\s]+)\s+([^\s]+)\s*(.*)$') { continue }
        $start = [Convert]::ToUInt64($Matches[1], 16)
        $end = [Convert]::ToUInt64($Matches[2], 16)
        if ($Address -ge $start -and $Address -lt $end) {
            return $line
        }
    }
    return "NOT_FOUND"
}

function Capture-RuntimePage {
    param([string]$Tid)
    $maps = Invoke-AdbText @("shell", "cat", "/proc/$mainPid/maps")
    $mapsPath = Join-Path $out ("maps-child-{0}.txt" -f $Tid)
    Set-Content -LiteralPath $mapsPath -Value $maps -Encoding utf8
    $match = [regex]::Match(
        $maps,
        '(?m)^([0-9a-f]+)-[0-9a-f]+\s+r-xp\s+00000000\b[^\r\n]*libcompatible\.so'
    )
    if (-not $match.Success) {
        Add-Content -LiteralPath $meta -Value ("runtime_page_tid={0} base=NOT_FOUND" -f $Tid)
        return
    }
    $base = [Convert]::ToUInt64($match.Groups[1].Value, 16)
    $tableOffset = [uint64]0x173000
    $tableAddress = $base + $tableOffset
    $tablePage = $tableAddress - ($tableAddress % 0x1000)
    $tableSkip = [uint64]($tablePage / 0x1000)
    $tableFile = Join-Path $out ("runtime-libcompatible-table-{0}.bin" -f $Tid)
    Save-AdbBinary @(
        "exec-out", "dd", "if=/proc/$mainPid/mem", "bs=4096",
        "skip=$tableSkip", "count=1", "status=none"
    ) $tableFile
    Add-Content -LiteralPath $meta -Value (
        "runtime_table_tid={0} base=0x{1:x} offset=0x{2:x} file={3}" -f $Tid, $base, $tableOffset, (Split-Path $tableFile -Leaf)
    )

    # The runtime table pointer is stored in the decoded page at table+0x150.
    # Strip the top MTE/PAC byte before reading the heap table page, then parse
    # table+0xd0 where the indirect kill/cleanup target is dispatched.
    $tableBytes = [IO.File]::ReadAllBytes($tableFile)
    $tableFieldOffset = [int](($tableAddress - $tablePage) + 0x150)
    $tablePointerRaw = Read-UInt64Little -Bytes $tableBytes -Offset $tableFieldOffset
    if ($null -eq $tablePointerRaw) {
        Add-Content -LiteralPath $meta -Value "runtime_table_pointer=READ_FAILED"
    } else {
        $tablePointer = Strip-TopByte $tablePointerRaw
        Add-Content -LiteralPath $meta -Value (
            "runtime_table_pointer_tid={0} raw=0x{1:x16} untagged=0x{2:x}" -f $Tid, $tablePointerRaw, $tablePointer
        )
        if ($tablePointer -ne 0) {
            $heapPage = $tablePointer - ($tablePointer % 0x1000)
            $heapSkip = [uint64]($heapPage / 0x1000)
            $heapFile = Join-Path $out ("runtime-dispatch-table-{0}.bin" -f $Tid)
            Save-AdbBinary @(
                "exec-out", "dd", "if=/proc/$mainPid/mem", "bs=4096",
                "skip=$heapSkip", "count=1", "status=none"
            ) $heapFile
            Add-Content -LiteralPath $meta -Value (
                "runtime_dispatch_page_tid={0} page=0x{1:x} file={2}" -f $Tid, $heapPage, (Split-Path $heapFile -Leaf)
            )
            $heapBytes = [IO.File]::ReadAllBytes($heapFile)
            $dispatchOffset = [int](($tablePointer - $heapPage) + 0xd0)
            $dispatchRaw = Read-UInt64Little -Bytes $heapBytes -Offset $dispatchOffset
            if ($null -eq $dispatchRaw) {
                Add-Content -LiteralPath $meta -Value "runtime_dispatch_target=READ_FAILED"
            } else {
                $dispatchTarget = Strip-TopByte $dispatchRaw
                $dispatchMap = Find-MapForAddress -Maps $maps -Address $dispatchTarget
                Add-Content -LiteralPath $meta -Value (
                    "runtime_dispatch_target_tid={0} raw=0x{1:x16} untagged=0x{2:x} map={3}" -f $Tid, $dispatchRaw, $dispatchTarget, $dispatchMap
                )
                if ($dispatchMap -ne "NOT_FOUND") {
                    $targetPage = $dispatchTarget - ($dispatchTarget % 0x1000)
                    $targetSkip = [uint64]($targetPage / 0x1000)
                    $targetFile = Join-Path $out ("runtime-dispatch-target-{0}.bin" -f $Tid)
                    Save-AdbBinary @(
                        "exec-out", "dd", "if=/proc/$mainPid/mem", "bs=4096",
                        "skip=$targetSkip", "count=1", "status=none"
                    ) $targetFile
                    Add-Content -LiteralPath $meta -Value (
                        "runtime_dispatch_target_page_tid={0} page=0x{1:x} offset=0x{2:x} file={3}" -f
                        $Tid, $targetPage, ($dispatchTarget - $targetPage), (Split-Path $targetFile -Leaf)
                    )
                }
            }
        } else {
            Add-Content -LiteralPath $meta -Value "runtime_dispatch_page=POINTER_ZERO"
        }
    }

    # Capture the runtime syscall-template page as well as the dispatcher and
    # caller pages.  The disk asm_kill symbol is near +0xcddb0, but the page
    # is decoded at runtime and may be copied into an anonymous executable
    # region before the watchdog uses it.
    foreach ($offset in @([uint64]0xcd000, [uint64]0x18000, [uint64]0x29000)) {
        $address = $base + $offset
        $page = $address - ($address % 0x1000)
        $skip = [uint64]($page / 0x1000)
        $file = Join-Path $out ("runtime-libcompatible-{0}-0x{1:x}.bin" -f $Tid, $offset)
        Save-AdbBinary @(
            "exec-out", "dd", "if=/proc/$mainPid/mem", "bs=4096",
            "skip=$skip", "count=2", "status=none"
        ) $file
        Add-Content -LiteralPath $meta -Value (
            "runtime_page_tid={0} base=0x{1:x} offset=0x{2:x} file={3}" -f $Tid, $base, $offset, (Split-Path $file -Leaf)
        )
    }
}

function Trace-Write {
    param([string]$Command)
    Invoke-Adb @("shell", $Command) | Out-Null
}

if ((Invoke-AdbText @("get-state")).Trim() -ne "device") {
    throw "whitelisted device $Serial is not online"
}

$trace = "/sys/kernel/tracing"
$perfRemote = "/data/local/tmp/nanaon-thread2-$($Package.Replace('.', '_')).data"
$perfLogRemote = "$perfRemote.log"
$traceState = Join-Path $out "trace-state-before.txt"
Save-AdbText @(
    "shell", "sh", "-c",
    "echo -n tracing_on=; cat $trace/tracing_on; echo -n events=; grep -h '^signal_generate\|^sched_process_fork' $trace/set_event 2>/dev/null || true"
) $traceState

Save-AdbText @("shell", "getprop", "ro.product.model") (Join-Path $out "device-model.txt")
Save-AdbText @("shell", "getprop", "ro.product.device") (Join-Path $out "device-name.txt")
Save-AdbText @("shell", "getprop", "ro.build.version.release") (Join-Path $out "device-android.txt")
Save-AdbText @("shell", "getprop", "ro.build.version.sdk") (Join-Path $out "device-sdk.txt")
Save-AdbText @("shell", "id") (Join-Path $out "device-id.txt")
Save-AdbText @("shell", "getenforce") (Join-Path $out "device-selinux.txt")

Invoke-Adb @("shell", "am", "force-stop", $Package) | Out-Null
Trace-Write "echo 0 > $trace/tracing_on; echo nop > $trace/current_tracer; echo > $trace/trace; echo 1 > $trace/events/signal/signal_generate/enable; echo 1 > $trace/events/sched/sched_process_fork/enable; echo 1 > $trace/tracing_on"
$started = Get-Date
$clock = [Diagnostics.Stopwatch]::StartNew()
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

$meta = Join-Path $out "meta.txt"
Set-Content -LiteralPath $meta -Value @(
    "started_at=$($started.ToString('o'))"
    "serial=$Serial"
    "package=$Package"
    "main_pid=$mainPid"
    "duration_sec=$DurationSec"
    "poll_milliseconds=$PollMilliseconds"
    "perf_duration_sec=$PerfDurationSec"
    "capture_runtime_page=$CaptureRuntimePage"
) -Encoding utf8
$samples = Join-Path $out "thread2-samples.tsv"
Set-Content -LiteralPath $samples -Value "elapsed_sec`t tid`t tracer_pid`t ppid`t wchan`t syscall" -Encoding utf8
$seen = @{}
$initialTid = $null
$perfStarted = $false
$perfPid = $null
$snapshots = @{}

try {
    while ($clock.Elapsed.TotalSeconds -le $DurationSec) {
        $elapsedReal = $clock.Elapsed.TotalSeconds
        Invoke-Adb @("shell", "kill", "-0", $mainPid) | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Add-Content -LiteralPath $meta -Value ("main_pid_gone_elapsed_sec={0:N3}" -f $elapsedReal)
            break
        }

        # Read task comm/status/wchan/syscall directly so ps column parsing
        # cannot hide a short-lived Thread-2 clone.
        # Use case matching instead of ``[ ... ]``: some vendor shells emit
        # a spurious ``[: worker: unexpected operator`` for transient comm
        # names while the task list is changing.
        # Use a comma delimiter and ``echo`` so the command remains parseable
        # when passed as one Windows adb shell argument; literal ``\t``/``\n``
        # escapes are stripped by that transport on this device.
        $probe = 'for p in /proc/' + $mainPid + '/task/*; do c=$(cat "$p/comm" 2>/dev/null); case "$c" in Thread-2) ;; *) continue ;; esac; t=${p##*/}; tr=$(grep ''^TracerPid:'' "$p/status" 2>/dev/null | cut -d: -f2); pp=$(grep ''^PPid:'' "$p/status" 2>/dev/null | cut -d: -f2); wc=$(cat "$p/wchan" 2>/dev/null); sc=$(cat "$p/syscall" 2>/dev/null); echo "$t,$c,$tr,$pp,$wc,$sc"; done'
        $probeOutput = Invoke-AdbText @("shell", $probe)
        foreach ($line in ($probeOutput -split "`r?`n")) {
            $line = $line.Trim()
            $fields = $line -split ",", 6
            if ($fields.Count -lt 6 -or $fields[0].Trim() -notmatch '^\d+$') { continue }
            $tid = $fields[0].Trim()
            $record = "{0:N3}`t{1}`t{2}`t{3}`t{4}`t{5}" -f $elapsedReal, $tid, $fields[2], $fields[3], $fields[4], $fields[5]
            Add-Content -LiteralPath $samples -Value $record
            if (-not $seen.ContainsKey($tid)) {
                $seen[$tid] = $elapsedReal
                $dir = Join-Path $out ("thread2-{0}" -f $tid)
                New-Item -ItemType Directory -Force -Path $dir | Out-Null
                Save-AdbText @("shell", "cat", "/proc/$mainPid/task/$tid/status") (Join-Path $dir "status-first.txt")
                Save-AdbText @("shell", "cat", "/proc/$mainPid/task/$tid/syscall") (Join-Path $dir "syscall-first.txt")
                Save-AdbText @("shell", "cat", "/proc/$mainPid/task/$tid/wchan") (Join-Path $dir "wchan-first.txt")
                Save-AdbText @("shell", "cat", "/proc/$mainPid/task/$tid/maps") (Join-Path $dir "maps-first.txt")
                Add-Content -LiteralPath $meta -Value ("thread2_tid={0} first_seen_elapsed_sec={1:N3}" -f $tid, $elapsedReal)
                if (-not $initialTid) {
                    $initialTid = $tid
                    Add-Content -LiteralPath $meta -Value "initial_thread2_tid=$tid"
                } elseif (-not $perfStarted -and $elapsedReal -ge 160) {
                    if ($CaptureRuntimePage) { Capture-RuntimePage -Tid $tid }
                    $remoteCmd = "rm -f '$perfRemote' '$perfLogRemote'; nohup /system/bin/simpleperf record -t $tid -e cpu-cycles:u -f 1000 --call-graph fp --duration $PerfDurationSec -o '$perfRemote' >'$perfLogRemote' 2>&1 </dev/null & echo `$!"
                    $perfPid = (Invoke-AdbText @("shell", $remoteCmd)).Trim()
                    Add-Content -LiteralPath $meta -Value ("simpleperf_started_tid={0} elapsed_sec={1:N3} remote_pid={2}" -f $tid, $elapsedReal, $perfPid)
                    $perfStarted = $true
                }
            }
        }

        # Capture each threshold once even when an ADB round-trip jumps over
        # the exact integer second (the old equality check could miss 30s).
        foreach ($checkpoint in @(0, 8, 30, 60, 120, 150, 180, 190)) {
            if ($elapsedReal -lt $checkpoint -or $snapshots.ContainsKey($checkpoint)) { continue }
            $stamp = "{0:D3}s" -f $checkpoint
            Save-AdbText @("shell", "ps", "-T", "-p", $mainPid) (Join-Path $out "tasks-$stamp.txt")
            Save-AdbText @("shell", "cat", "/proc/$mainPid/maps") (Join-Path $out "maps-$stamp.txt")
            if ($checkpoint -in @(8, 30, 60, 120, 150, 180, 190)) { Save-Screenshot (Join-Path $out "screen-$stamp.png") }
            $snapshots[$checkpoint] = $true
        }
        Start-Sleep -Milliseconds $PollMilliseconds
    }
}
finally {
    # Every cleanup action is best-effort.  In particular, short runs do not
    # start simpleperf, so pulling its absent output must not skip force-stop.
    try { Save-AdbText @("shell", "cat", "$trace/trace") (Join-Path $out "ftrace-final.txt") } catch { }
    try { Save-AdbText @("shell", "cat", "$trace/tracing_on") (Join-Path $out "tracing-on-final.txt") } catch { }
    try { Trace-Write "echo 0 > $trace/tracing_on; echo 0 > $trace/events/signal/signal_generate/enable; echo 0 > $trace/events/sched/sched_process_fork/enable; echo > $trace/trace" } catch { }
    try {
        Invoke-Adb @("shell", "dumpsys", "activity", "exit-info", $Package) |
            Set-Content -LiteralPath (Join-Path $out "exit-info.txt") -Encoding utf8
    } catch { }
    try { Save-AdbText @("shell", "logcat", "-d", "-v", "threadtime") (Join-Path $out "logcat-final.txt") } catch { }
    $perfLocal = Join-Path $out "perf.data"
    if ($perfStarted) {
        try {
            Invoke-AdbText @("pull", $perfRemote, $perfLocal) |
                Set-Content -LiteralPath (Join-Path $out "perf-pull.txt") -Encoding utf8
        } catch {
            Set-Content -LiteralPath (Join-Path $out "perf-pull.txt") -Value ("perf-pull-failed: " + $_.Exception.Message) -Encoding utf8
        }
        try { Save-AdbText @("shell", "cat", $perfLogRemote) (Join-Path $out "perf-record.log") }
        catch { Set-Content -LiteralPath (Join-Path $out "perf-record.log") -Value "perf-log-unavailable" -Encoding utf8 }
    } else {
        Set-Content -LiteralPath (Join-Path $out "perf-pull.txt") -Value "perf-not-started" -Encoding utf8
        Set-Content -LiteralPath (Join-Path $out "perf-record.log") -Value "perf-not-started" -Encoding utf8
    }
    try { Invoke-Adb @("shell", "rm", "-f", $perfRemote, $perfLogRemote) | Out-Null } catch { }
    try { Invoke-Adb @("shell", "am", "force-stop", $Package) | Out-Null } catch { }
    if ($meta) { Add-Content -LiteralPath $meta -Value "finished_at=$((Get-Date).ToString('o'))" }
}

Write-Output "captured Thread-2 perf window for $Package pid=$mainPid into $out"
