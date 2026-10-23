# PhishGuard AI 2.0

**IBM SkillsBuild Cyber Security BootCamp 2026 | BharatCares**  
**Prepared by: Debartha Saha**

## Project overview
PhishGuard AI 2.0 is a Python/Jupyter Notebook-based defensive cybersecurity prototype that analyses suspicious email/SMS text and URLs using transparent, rule-based indicators. It produces a heuristic risk score (0–100), evidence-backed findings, explanations, and defensive recommendations. The core system operates entirely offline and does not visit submitted URLs.

## Implemented features
- Local analysis of email/SMS message text and URLs — no network requests.
- URL parsing using Python's stdlib `urllib.parse` — the URL is never fetched.
- Rule-based indicators for urgency language, credential requests, payment language, link presence, suspicious URL structures, and selected sender/context mismatches.
- Explainable findings with rule ID, title, severity, evidence, explanation, recommendation, and point contribution.
- Heuristic risk score from 0 to 100 with Low, Medium, and High categories.
- Score deduplication: the highest contribution per rule ID is used; the same rule cannot inflate the score by firing twice.
- Synthetic demonstration examples covering suspicious, legitimate, and ambiguous messages.
- Colour-coded horizontal bar chart of example risk scores with threshold markers.
- JSON export of investigation results.
- Automated test suite: 96 tests covering all major code paths.

## Detection rules
| Rule | Title | Severity | Points |
|------|-------|----------|--------|
| MSG001 | Urgency or pressure language | Medium | 12 |
| MSG002 | Credential or verification request | High | 25 |
| MSG003 | Payment or financial information language | Medium | 15 |
| MSG004 | Link present in message | Low | 5 |
| MSG005 | Public email provider for an organisation claim | Low | 10 |
| URL001 | Unusual URL scheme | Medium | 20 |
| URL002 | Hostname could not be parsed | High | 35 |
| URL003 | IP address used as hostname | Medium | 15 |
| URL004 | Internationalized/punycode hostname | Medium | 20 |
| URL005 | Many hostname labels | Low | 10 |
| URL006 | User information embedded in URL | High | 30 |
| URL007 | Security-themed hostname wording | Low | 8 |
| URL008 | Connection does not use HTTPS | Low | 8 |
| URL009 | Repeated URL encoding | Low | 8 |

URL rules triggered by embedded links in a message appear as `EMBEDDED_URL001`, etc.

## Dataset
No external dataset is required. The notebook includes a small set of **synthetic demonstration examples** created for this project. They are not real user messages and do not represent a validated benchmark dataset. To extend evaluation, create a properly licensed, labeled dataset and document its source and limitations.

## Technologies used
- Python 3.10 or newer
- Jupyter Notebook
- pandas — tabular display of results
- matplotlib — risk-score bar chart
- Python standard library: `re`, `urllib.parse`, `ipaddress`, `json`, `datetime`

## Project files
| File | Description |
|------|-------------|
| `DebarthaSaha_PhishGuardAI.ipynb` | Complete notebook — imports the engine, includes inline fallback, runs examples and visualization. |
| `phishguard_engine.py` | Detection engine module — imported by both the notebook and the test suite. |
| `requirements.txt` | Python dependencies (`pandas`, `matplotlib`, `jupyter`). |
| `DebarthaSaha_ProjectReport.docx` | Full project report. |
| `README.md` | This file. |
| `tests/test_phishguard.py` | Automated test suite (96 tests). |

## Setup
Use Python 3.10 or newer.

```bash
python -m venv .venv
```

Activate the environment:

**Windows:**
```bash
.venv\Scripts\activate
```

**macOS/Linux:**
```bash
source .venv/bin/activate
```

Install dependencies:
```bash
python -m pip install -r requirements.txt
```

## Running the notebook
```bash
jupyter notebook
```

Open `DebarthaSaha_PhishGuardAI.ipynb` and select **Kernel → Restart & Run All** to execute all cells from top to bottom.

## How to use
1. Run all cells in order.
2. Review the built-in synthetic examples in the summary table and bar chart.
3. Edit the sample message and sender in the manual-analysis cell (Cell 6).
4. Call `analyze_message(message, sender=...)` for email/SMS text.
5. Call `analyze_url(url)` for URL structure analysis.
6. Call `print_report(result)` to display findings.
7. Run the JSON export cell to save a sample investigation report.

## Example usage (Python)
```python
from phishguard_engine import analyze_message, analyze_url, print_report

# Analyse a message
result = analyze_message(
    "Act now! Enter your password at http://verify.example.invalid/",
    sender="noreply@gmail.com"
)
print_report(result)

# Analyse a URL alone
url_result = analyze_url("http://user:pw@192.0.2.1/login")
print_report(url_result)
```

## Risk score interpretation
The score is a transparent heuristic based on configured rule weights. Current categories:

| Score | Level |
|-------|-------|
| 0–24 | Low |
| 25–49 | Medium |
| 50–100 | High |

This score is **not a calibrated probability**. One indicator alone does not prove that a message is malicious, and a low score does **not** prove that it is safe. The summary text makes this explicit.

## Running the tests
```bash
python -m pytest tests/ -v
```

Or without pytest:
```bash
python -m unittest discover -s tests -v
```

**Result on Python 3.14:** 96 tests collected, 96 passed, 0 failed (≈3 s).

Tests cover:
1. Empty and invalid inputs
2. Credential-request messages
3. Urgency and payment messages
4. Legitimate messages (false-positive control)
5. URLs with unusual structures
6. Malformed URLs
7. URL extraction from message text
8. Score boundaries and risk categories
9. Duplicate-finding and score deduplication
10. JSON serialisation and report generation
11. Graceful handling of optional or missing fields
12. Integration smoke tests

## Safety and limitations
- Submitted URLs are parsed locally and are **never** visited, downloaded, or resolved via DNS.
- No real-time threat-intelligence lookups are performed by the core project.
- No live LLM/AI provider is required or contacted by default.
- The prototype may produce false positives and false negatives.
- Do not submit passwords, one-time codes, private messages, or confidential information.
- Verify suspicious requests through official channels found independently.
- This is an educational prototype, **not** a production security product.

## Future work (not implemented)
- Optional AI explanations grounded in existing findings, disabled by default.
- Opt-in reputation enrichment through documented threat-intelligence APIs.
- Persistent case history and correlation between investigations.
- Expanded evaluation with a labeled, appropriately licensed dataset.
