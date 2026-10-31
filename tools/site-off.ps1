# Takes the portal offline. The background detection job keeps running.
Get-Process cloudflared -ErrorAction SilentlyContinue | Stop-Process -Force
Get-CimInstance Win32_Process -Filter "Name = 'pythonw.exe' OR Name = 'python.exe'" |
    Where-Object { $_.CommandLine -like '*vigil mdr*portal.py*' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Write-Host 'Vigil is OFFLINE.'
