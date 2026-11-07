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

### 2026-10-31 23:00

**Files changed (last 24h):**
- `.gitignore`
- `adapters/__init__.py`
- `adapters/limacharlie.py`
- `analyze.py`
- `build_prompt.py`
- `charts.py`
- `convert_test.py`
- `correlate.py`
- `db.py`
- `defang.py`
- `docs/architecture.svg`
- `docs/implementation.html`
- `docs/setup-from-scratch.html`
- `docs/site-on-guide.html`
- `docs/to_turn_on_your_portal.pdf`
- `docs/Vigil-MDR-Implementation.pdf`
- `docs/Vigil-MDR-Setup-Guide.pdf`
- `fetch_test.py`
- `instructions.md`
- `PLAN.md`
- `PLAN.txt`
- `poll.py`
- `portal.py`
- `process_tree.py`
- `prompts/core.md`
- `prompts/playbooks/c2_exfil.md`
- `prompts/playbooks/credential_access.md`
- `prompts/playbooks/defense_evasion.md`
- `prompts/playbooks/discovery_lateral.md`
- `prompts/playbooks/execution.md`
- `prompts/playbooks/forensics.md`
- `prompts/playbooks/impact_ransomware.md`
- `prompts/playbooks/initial_access.md`
- `prompts/playbooks/linux.md`
- `prompts/playbooks/persistence.md`
- `prompts/playbooks/privilege_escalation.md`
- `README.md`
- `report.py`
- `requirements.txt`
- `schema.sql`
- `schema/verdict.schema.json`
- `static/app.js`
- `static/htmx.min.js`
- `static/inter.woff2`
- `static/logo.svg`
- `static/style.css`
- `STATUS_EMAIL.txt`
- `step6_test.py`
- `templates/_review.html`
- `templates/_table.html`
- `templates/_tree.html`
- `templates/base.html`
- `templates/customer.html`
- `templates/dashboard.html`
- `templates/error.html`
- `templates/incident.html`
- `templates/login.html`
- `templates/metrics.html`
- `tools/daily-status.ps1`
- `tools/set-portal-password.ps1`
- `tools/site-off.cmd`
- `tools/site-off.ps1`
- `tools/site-on.cmd`
- `tools/site-on.ps1`
- `validate.py`

**Commits (last 24h):**
- 9a11cfa Add site on and off switches and portal guide
- 5349393 Add beginner build walkthrough to implementation guide
- 0d81821 Add analyst workflow, customer reports and security dashboard
- fe8f69e Add step-by-step setup guide for new users
- 05d6176 Add portal, login, process trees, playbooks and implementation guide
- b9e39c8 Add PostgreSQL case store
- 097f1bb Add README and project notes
- 2433ee3 Add usage instructions, architecture diagram, and remaining work
- de723da Note that Vigil gathers data only from LimaCharlie
- 7390b25 Add Vigil MDR detection pipeline

### 2026-11-03 15:56

**Files changed (last 24h):**
- None

**Commits (last 24h):**
- None

### 2026-11-03 21:00

**Files changed (last 24h):**
- None

**Commits (last 24h):**
- None

### 2026-11-03 23:45

**Files changed (last 24h):**
- None

**Commits (last 24h):**
- None

### 2026-11-07 17:32

**Files changed (last 24h):**
- None

**Commits (last 24h):**
- None
