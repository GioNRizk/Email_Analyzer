# 🛡️ Email Threat Analyzer
Built during internship at **Atria Solutions** — automated email security analysis pipeline with SOC dashboard.

---

## What it does
Fetches emails via IMAP, analyzes them using 9 threat intelligence sources and a local LLM, then displays results on a web dashboard.

---


## Project Structure
```
Email_Analyzer/
├── config/settings.py        # All constants 
├── core/
│   ├── database.py           # MySQL queries
│   ├── email_parser.py       # .eml parsing and IP extraction
│   └── threat_intel.py       # All 9 threat intel API calls
├── utils/logger.py           # Logging
├── dashboard/
│   ├── app.py                # Flask server
│   └── templates/index.html  # SOC dashboard
├── scripts/
│   ├── parse_headers.py
│   ├── llm_analysis.py
│   └── recheck.py
├── reputation.py             # Step 3 runner
└── .env                      # Credentials (not committed)
```

---

## Setup
```bash
git clone https://github.com/GioNRizk/Email_Analyzer.git
pip install -r requirements.txt
cp .env.example .env        # fill in your credentials
python reputation.py        # run Step 3
python dashboard/app.py     # open http://localhost:5000
```

---

## Stack
Python 3.12 · Flask · MySQL · Ollama phi3 · AbuseIPDB · AlienVault OTX · GreyNoise · URLhaus · ThreatFox · Pulsedive
