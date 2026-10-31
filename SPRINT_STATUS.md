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
| 6 | Case store | Incidents saved in PostgreSQL | Done | 2026-10-31 | 2026-10-31 |
| 7 | Portal | FastAPI + HTMX with approve/reject | Done | 2026-10-31 | 2026-10-31 |

## Remaining work

Work through these in order. Data comes only from LimaCharlie, with no sandbox steps.

### Confirm
- [ ] See one new LimaCharlie detection reach `data/incidents/` by itself.
- [ ] Find out whether Orborus access to LSASS is normal for that tool.

### Improve results
- [ ] Add code rules for known tools touching LSASS, and block contradictory verdicts.
- [ ] Test a larger Ollama model if the laptop can run it.
- [ ] Tune Stage 4 grouping and scoring for Orborus incidents.
- [ ] Stop Ollama marking every incident `true_positive` with high confidence.
- [ ] Correct ATT&CK mistakes in Ollama's summaries.
- [ ] Build an eval set from labelled LimaCharlie detections.
- [ ] Measure verdict accuracy, then re-test after each prompt or model change.
- [ ] Tune noisy detection rules and keep the rules in Git.

### Build the rest of the diagram
- [x] Stage 6: create PostgreSQL tables for events, detections, incidents and analyses.
- [x] Stage 6: save incidents to PostgreSQL instead of files.
- [ ] Stage 6: confirm PostgreSQL starts by itself after a restart.
- [ ] Stage 6: set up regular database backups.
- [x] Stage 7: build the FastAPI and HTMX dashboard and incident pages.
- [x] Stage 7: add HTML and PDF reports to the portal.
- [x] Analyst review: add approve, reject and close.
- [ ] Stage 7: decide whether the portal should start by itself at login.
- [ ] Feedback loop: use review decisions to tune rules.

### Optional later
- [ ] Email or desktop alerts for high-score incidents.
- [ ] A report generated automatically each day.
- [ ] Linux VMs or Sysmon for wider coverage.

## Daily log

### 2026-10-31 15:20

**Files changed (last 24h):**
- `tools/daily-status.ps1`

**Commits (last 24h):**
- None
