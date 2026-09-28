$procs = Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Where-Object { $_.CommandLine -like '*dist\index.js*' }
foreach ($p in $procs) { Stop-Process -Id $p.ProcessId -Force; Write-Output ("killed " + $p.ProcessId) }
Start-Sleep -Seconds 2
Start-Process cmd.exe -ArgumentList '/c','set NODE_ENV=production&& set PORT=8321&& node dist\index.js >> prod-preview.log 2>&1' -WindowStyle Hidden -WorkingDirectory (Get-Location)
Start-Sleep -Seconds 7
try {
  $r = Invoke-WebRequest -Uri http://127.0.0.1:8321/health -UseBasicParsing -TimeoutSec 15
  Write-Output ("health: " + $r.StatusCode)
} catch {
  Write-Output ("health check failed: " + $_.Exception.Message)
}
