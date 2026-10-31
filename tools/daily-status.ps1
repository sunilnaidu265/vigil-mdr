# Appends a dated entry to SPRINT_STATUS.md: files changed and commits in the last 24 hours.
$root = Split-Path -Parent $PSScriptRoot
$statusFile = Join-Path $root 'SPRINT_STATUS.md'
$since = (Get-Date).AddDays(-1)

$changed = Get-ChildItem -LiteralPath $root -Recurse -File -Force |
    Where-Object {
        $_.FullName -notmatch '\\(\.git|\.venv|__pycache__|data)\\' -and
        $_.FullName -ne $statusFile -and
        $_.LastWriteTime -gt $since
    } |
    ForEach-Object { $_.FullName.Substring($root.Length + 1).Replace('\', '/') } |
    Sort-Object

$commits = @()
if (Test-Path -LiteralPath (Join-Path $root '.git')) {
    $commits = @(& git -C $root log --since='24 hours ago' --format='%h %s')
}

$lines = @('', "### $(Get-Date -Format 'yyyy-MM-dd HH:mm')", '', '**Files changed (last 24h):**')
if ($changed) { $lines += $changed | ForEach-Object { "- ``$_``" } } else { $lines += '- None' }
$lines += @('', '**Commits (last 24h):**')
if ($commits) { $lines += $commits | ForEach-Object { "- $_" } } else { $lines += '- None' }

Add-Content -LiteralPath $statusFile -Value $lines -Encoding utf8
