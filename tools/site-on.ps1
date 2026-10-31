# Starts the portal in public mode with a Cloudflare quick tunnel, then prints the address.
$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root
& "$PSScriptRoot\site-off.ps1" | Out-Null

foreach ($name in 'VIGIL_DB_PASSWORD', 'VIGIL_PORTAL_HASH', 'VIGIL_SESSION_SECRET') {
    Set-Item "Env:$name" ([Environment]::GetEnvironmentVariable($name, 'User'))
}
$env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
$env:VIGIL_PUBLIC = '1'
Start-Process "$root\.venv\Scripts\pythonw.exe" -ArgumentList "`"$root\portal.py`"" -WorkingDirectory $root | Out-Null
Remove-Item Env:VIGIL_PUBLIC

$log = "$root\data\tunnel.log"
Remove-Item -LiteralPath $log -ErrorAction SilentlyContinue
Start-Process cloudflared -ArgumentList 'tunnel', '--no-autoupdate', '--logfile', "`"$log`"", '--url', 'http://127.0.0.1:8080' -WindowStyle Hidden | Out-Null

$address = $null
$deadline = (Get-Date).AddSeconds(45)
while (-not $address -and (Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 2
    if (Test-Path -LiteralPath $log) {
        $match = Select-String -LiteralPath $log -Pattern 'https://[a-z0-9-]+\.trycloudflare\.com' | Select-Object -First 1
        if ($match) { $address = $match.Matches[0].Value }
    }
}

if ($address) {
    Write-Host "Vigil is ONLINE: $address"
    Write-Host 'Sign in with your portal password. Run site-off when you finish.'
} else {
    Write-Host 'The tunnel did not start. Check data\tunnel.log, then try again.'
    exit 1
}
