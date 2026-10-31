# Vigil MDR

Vigil is a personal Managed Detection and Response (MDR) lab project. It collects LimaCharlie detections from a Windows sandbox, groups related alerts into scored incidents, and uses a local AI model to suggest a verdict for a human analyst to review.

It's a learning project, not a production security service. It doesn't block attacks, and its AI verdicts haven't been measured for accuracy yet.

![How Vigil MDR works](docs/architecture.svg)

## What works today

- Pulls new LimaCharlie detections every 5 minutes through a Windows scheduled task.
- Masks passwords and tokens found in command lines before saving detections.
- Groups detections into incidents by shared process and time window.
- Scores incidents using rule severity, ATT&CK techniques and access to LSASS.
- Sends each incident to a local Ollama model, so detection data stays on the laptop.
- Validates the model's JSON and rejects evidence IDs it makes up.
- Builds an HTML report with indicators, command lines, hashes and a timeline.

## Project status

| Stage | Status |
|---|---|
| 1. Endpoints | Done |
| 2. Collect | Done |
| 3. Detect | Working, needs tuning |
| 4. Correlate | Working, needs tuning |
| 5. AI Analyze | Running, accuracy not measured |
| 6. Case Store | Planned |
| 7. Web Portal | Planned |
| Analyst review and feedback loop | Planned |

The detailed task list is in [SPRINT_STATUS.md](SPRINT_STATUS.md).

## Tech stack

- **Detection:** LimaCharlie, with Sigma and managed rules
- **Pipeline:** Python and Windows Task Scheduler
- **AI:** Ollama with the `qwen3:4b` model
- **Planned:** PostgreSQL, FastAPI and HTMX

## Project layout

| Path | Purpose |
|---|---|
| `poll.py` | Runs the pipeline: fetch, mask, correlate and analyze |
| `correlate.py` | Groups detections and scores incidents |
| `analyze.py` | Sends incidents to Ollama |
| `validate.py` | Checks the model's answers |
| `report.py` | Builds the HTML report |
| `adapters/` | Converts LimaCharlie detections into a simple format |
| `prompts/` | Instructions for the AI model |
| `schema/` | Required format for AI verdicts |
| `tools/` | Daily status script |
| `docs/` | Architecture diagram |

## Getting started

Setup, daily use, settings and troubleshooting are all in [instructions.md](instructions.md).

## Data and secrets

Detection data stays in `data/`, which Git ignores. LimaCharlie credentials are stored in Windows user environment variables and never in the code.
