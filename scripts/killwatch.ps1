# Black-box watcher: log every python.exe process deletion + scene snapshot,
# plus creation of likely-killer processes. Run: powershell -File killwatch.ps1
$log = Join-Path $PSScriptRoot "..\logs\killwatch.log"
$qDel = "SELECT * FROM __InstanceDeletionEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name LIKE 'python%'"
$qNew = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process' AND (TargetInstance.Name LIKE 'taskkill%' OR TargetInstance.Name LIKE '%QQPC%' OR TargetInstance.Name LIKE 'TP%' OR TargetInstance.Name LIKE '360%' OR TargetInstance.Name LIKE 'ZhuDong%')"
$del = Register-WmiEvent -Query $qDel -SourceIdentifier pyDel -Action {
    $t = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$t PYTHON_DELETED"
    try {
        $procs = Get-CimInstance Win32_Process | Select-Object -First 400 |
                 ForEach-Object { "$($_.ProcessId)=$($_.Name)" }
        $line += " SCENE:" + ($procs -join ",")
    } catch { $line += " SCENE_ERR" }
    Add-Content -Path $using:log -Value $line -Encoding UTF8
}
$new = Register-WmiEvent -Query $qNew -SourceIdentifier killerNew -Action {
    $t = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $n = $Event.SourceEventArgs.NewEvent.TargetInstance.Name
    $p = $Event.SourceEventArgs.NewEvent.TargetInstance.ParentProcessId
    Add-Content -Path $using:log -Value "$t KILLER_SPAWN $n parent=$p" -Encoding UTF8
}
Add-Content -Path $log -Value ("$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') WATCHER_UP") -Encoding UTF8
while ($true) { Start-Sleep -Seconds 60 }
