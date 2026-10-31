# Vigil MDR – Sprint Status

Update the Sprint plan table by hand as stages move. The Daily log is added
automatically by `tools/daily-status.ps1`.

## Sprint plan

| Stage | Name | Goal | Status | Started | Finished |
|---|---|---|---|---|---|
| 1 | Endpoints | Sandbox Windows VM reporting to LimaCharlie | Done | | 2026-10-30 |
| 2 | Collect | `poll.py` pulls detections every 5 minutes (replaced the webhook) | Done, recovery test pending | 2026-10-31 | |
| 3 | Detect | ATT&CK-tagged rules fire on Atomic Red Team tests | Working, needs tuning | | |
| 4 | Correlate | Related detections become one scored incident | Working, needs tuning | 2026-10-31 | |
| 5 | AI Analyze | Local Ollama triage with validated JSON | Running, accuracy not measured | 2026-10-31 | |
| 6 | Case store | Incidents saved in PostgreSQL | Not started | | |
| 7 | Portal | FastAPI + HTMX with approve/reject | Not started | | |

## Daily log

### 2026-10-31 15:20

**Files changed (last 24h):**
- `tools/daily-status.ps1`

**Commits (last 24h):**
- None
