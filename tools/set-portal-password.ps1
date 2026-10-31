# Sets the portal password. The hash and session secret are saved as Windows user variables.
function Read-Secret($prompt) {
    $secure = Read-Host $prompt -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}

$root = Split-Path -Parent $PSScriptRoot
$first = Read-Secret 'Choose a portal password, at least 14 characters (nothing will appear)'
$second = Read-Secret 'Type it again'
if ($first -cne $second -or $first.Length -lt 14) {
    Write-Host 'Passwords did not match, or it was under 14 characters. Nothing was saved.'
    Start-Sleep -Seconds 6
    exit 1
}

$python = @'
import hashlib, os, secrets
password = os.environ["VIGIL_NEW_PASSWORD"].encode()
salt = secrets.token_bytes(16)
digest = hashlib.scrypt(password, salt=salt, n=2**14, r=8, p=1)
print(salt.hex() + "$" + digest.hex())
print(secrets.token_hex(32))
'@
$scriptFile = [IO.Path]::GetTempFileName()
Set-Content -LiteralPath $scriptFile -Value $python -Encoding ascii
$env:VIGIL_NEW_PASSWORD = $first  # a pipe would add a line break to the password
$output = & "$root\.venv\Scripts\python.exe" $scriptFile
Remove-Item -LiteralPath Env:VIGIL_NEW_PASSWORD
Remove-Item -LiteralPath $scriptFile
[Environment]::SetEnvironmentVariable('VIGIL_PORTAL_HASH', $output[0], 'User')
[Environment]::SetEnvironmentVariable('VIGIL_SESSION_SECRET', $output[1], 'User')
Write-Host 'Password saved. This window will close.'
Start-Sleep -Seconds 3
