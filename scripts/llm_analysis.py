# =============================================================
# scripts/llm_analysis.py
# Step 4: LLM Analysis using Groq (cloud) — llama-3.3-70b
# Analyzes emails as a Senior SOC Analyst
# =============================================================

import os
import sys
import json
import time
import requests
#step 4
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.database import Database
from core.email_parser import EmailParser
from config.settings import GROQ_API_KEY
from utils.logger import get_logger

logger = get_logger("llm_analysis")
parser = EmailParser()

# ── Add columns if missing ────────────────────────────────────
def prepare_db(db: Database) -> None:
    db.add_columns([
        "ALTER TABLE email_reports ADD COLUMN llm_verdict VARCHAR(50)",
        "ALTER TABLE email_reports ADD COLUMN llm_confidence VARCHAR(20)",
        "ALTER TABLE email_reports ADD COLUMN llm_risk_score INT",
        "ALTER TABLE email_reports ADD COLUMN llm_reason TEXT",
        "ALTER TABLE email_reports ADD COLUMN groq_verdict VARCHAR(50)",
        "ALTER TABLE email_reports ADD COLUMN groq_confidence VARCHAR(20)",
        "ALTER TABLE email_reports ADD COLUMN groq_risk_score INT",
        "ALTER TABLE email_reports ADD COLUMN groq_reason TEXT",
        "ALTER TABLE email_reports ADD COLUMN groq_analysis TEXT",
    ])

# ── SOC Analyst Prompt ────────────────────────────────────────
def build_soc_prompt(row: dict, body: str) -> str:
    return f"""
You are a Senior SOC Analyst. Analyze this email and respond ONLY with JSON.

FROM:    {row['from_address']}
SUBJECT: {row['subject']}
DOMAIN:  {row['sender_domain']}
SPF: {row['spf']} | DKIM: {row['dkim']} | DMARC: {row['dmarc']}
IP: {row.get('sender_ip','unknown')} | AbuseIPDB: {row.get('abuse_score',0)}/100 | OTX: {row.get('otx_pulses',0)} pulses
Domain Age: {row.get('domain_age_days',-1)} days | SSL: {row.get('ssl_info','unknown')}
URLhaus: {row.get('urlhaus_status','clean')} | ThreatFox: {row.get('threatfox_status','clean')}

BODY:
{body}

RULES:
- Brand impersonation + domain mismatch → phishing
- SPF+DKIM+DMARC all fail → phishing or bec
- Payment/crypto/fund transfer request → bec
- New domain < 180 days + auth failures → phishing
- Known brand, all auth pass, normal content → benign

Respond ONLY with this JSON, no markdown, no backticks:
{{
  "verdict": "phishing/bec/spam/benign",
  "confidence": "high/medium/low",
  "risk_score": 0-100,
  "reason": "one line summary",
  "flags": ["key red flag 1", "key red flag 2", "key red flag 3"],
  "analysis": {{
    "authentication": "one line",
    "sender":         "one line",
    "threat_intel":   "one line",
    "content":        "one line",
    "conclusion":     "one line"
  }}
}}
"""

# ── Groq API Call ─────────────────────────────────────────────
def analyze_with_groq(row: dict, body: str) -> dict | None:
    """Groq cloud LLM — llama-3.3-70b-versatile"""
    try:
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type":  "application/json"
            },
            json={
                "model":       "llama-3.3-70b-versatile",
                "messages":    [{"role": "user", "content": build_soc_prompt(row, body)}],
                "temperature": 0.1,
                "max_tokens":  1000
            },
            timeout=30
        )
        data = response.json()

        # Handle rate limit
        if "error" in data:
            logger.warning(f"Groq error: {data['error'].get('message','unknown')}")
            return None

        result = data["choices"][0]["message"]["content"]
        result = result.replace("```json", "").replace("```", "").strip()

        # Extract JSON safely
        start = result.find("{")
        if start != -1:
            depth = 0
            for i, char in enumerate(result[start:], start):
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        return json.loads(result[start:i+1])
    except Exception as e:
        logger.warning(f"Groq failed: {e}")
    return None

# ── Print SOC report ──────────────────────────────────────────
def print_soc_report(result: dict) -> None:
    verdict = result["verdict"].upper()
    score   = result["risk_score"]
    conf    = result["confidence"].upper()
    emoji   = {
        "PHISHING": "🚨",
        "BEC":      "⚠️",
        "SPAM":     "📢",
        "BENIGN":   "✅"
    }.get(verdict, "❓")

    print(f"\n  {emoji} {verdict} | {score}/100 | {conf}")

    # Key flags
    flags = result.get("flags", [])
    if flags:
        print(f"  FLAGS:   {' | '.join(flags)}")

    # One line per category
    a = result.get("analysis", {})
    print(f"  AUTH:    {a.get('authentication', '—')}")
    print(f"  SENDER:  {a.get('sender', '—')}")
    print(f"  INTEL:   {a.get('threat_intel', '—')}")
    print(f"  CONTENT: {a.get('content', '—')}")
    print(f"  VERDICT: {a.get('conclusion', '—')}")
    print(f"  SUMMARY: {result.get('reason', '—')}")

# ── Main ──────────────────────────────────────────────────────
# =============================================================
# scripts/llm_analysis.py
# Step 4: LLM Analysis using Groq (cloud) — llama-3.3-70b
# Analyzes emails as a Senior SOC Analyst
# =============================================================

import os
import sys
import json
import time
import requests

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.database import Database
from core.email_parser import EmailParser
from config.settings import GROQ_API_KEY
from utils.logger import get_logger

logger = get_logger("llm_analysis")
parser = EmailParser()

# ── Add columns if missing ────────────────────────────────────
def prepare_db(db: Database) -> None:
    db.add_columns([
        "ALTER TABLE email_reports ADD COLUMN llm_verdict VARCHAR(50)",
        "ALTER TABLE email_reports ADD COLUMN llm_confidence VARCHAR(20)",
        "ALTER TABLE email_reports ADD COLUMN llm_risk_score INT",
        "ALTER TABLE email_reports ADD COLUMN llm_reason TEXT",
        "ALTER TABLE email_reports ADD COLUMN groq_verdict VARCHAR(50)",
        "ALTER TABLE email_reports ADD COLUMN groq_confidence VARCHAR(20)",
        "ALTER TABLE email_reports ADD COLUMN groq_risk_score INT",
        "ALTER TABLE email_reports ADD COLUMN groq_reason TEXT",
        "ALTER TABLE email_reports ADD COLUMN groq_analysis TEXT",
    ])

# ── SOC Analyst Prompt ────────────────────────────────────────
def build_soc_prompt(row: dict, body: str) -> str:
    return f"""
You are a Senior SOC Analyst. Analyze this email and respond ONLY with JSON.

FROM:    {row['from_address']}
SUBJECT: {row['subject']}
DOMAIN:  {row['sender_domain']}
SPF: {row['spf']} | DKIM: {row['dkim']} | DMARC: {row['dmarc']}
IP: {row.get('sender_ip','unknown')} | AbuseIPDB: {row.get('abuse_score',0)}/100 | OTX: {row.get('otx_pulses',0)} pulses
Domain Age: {row.get('domain_age_days',-1)} days | SSL: {row.get('ssl_info','unknown')}
URLhaus: {row.get('urlhaus_status','clean')} | ThreatFox: {row.get('threatfox_status','clean')}

BODY:
{body}

RULES:
- Brand impersonation + domain mismatch → phishing
- SPF+DKIM+DMARC all fail → phishing or bec
- Payment/crypto/fund transfer request → bec
- New domain < 180 days + auth failures → phishing
- Known brand, all auth pass, normal content → benign

Respond ONLY with this JSON, no markdown, no backticks:
{{
  "verdict": "phishing/bec/spam/benign",
  "confidence": "high/medium/low",
  "risk_score": 0-100,
  "reason": "one line summary",
  "flags": ["key red flag 1", "key red flag 2", "key red flag 3"],
  "analysis": {{
    "authentication": "one line",
    "sender":         "one line",
    "threat_intel":   "one line",
    "content":        "one line",
    "conclusion":     "one line"
  }}
}}
"""

# ── Groq API Call ─────────────────────────────────────────────
def analyze_with_groq(row: dict, body: str) -> dict | None:
    """Groq cloud LLM — llama-3.3-70b-versatile"""
    try:
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type":  "application/json"
            },
            json={
                "model":       "llama-3.3-70b-versatile",
                "messages":    [{"role": "user", "content": build_soc_prompt(row, body)}],
                "temperature": 0.1,
                "max_tokens":  1000
            },
            timeout=30
        )
        data = response.json()

        # Handle rate limit
        if "error" in data:
            logger.warning(f"Groq error: {data['error'].get('message','unknown')}")
            return None

        result = data["choices"][0]["message"]["content"]
        result = result.replace("```json", "").replace("```", "").strip()

        # Extract JSON safely
        start = result.find("{")
        if start != -1:
            depth = 0
            for i, char in enumerate(result[start:], start):
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        return json.loads(result[start:i+1])
    except Exception as e:
        logger.warning(f"Groq failed: {e}")
    return None

# ── Print SOC report ──────────────────────────────────────────
def print_soc_report(result: dict) -> None:
    verdict = result["verdict"].upper()
    score   = result["risk_score"]
    conf    = result["confidence"].upper()
    emoji   = {
        "PHISHING": "🚨",
        "BEC":      "⚠️",
        "SPAM":     "📢",
        "BENIGN":   "✅"
    }.get(verdict, "❓")

    print(f"\n  {emoji} {verdict} | {score}/100 | {conf}")

    # Key flags
    flags = result.get("flags", [])
    if flags:
        print(f"  FLAGS:   {' | '.join(flags)}")

    # One line per category
    a = result.get("analysis", {})
    print(f"  AUTH:    {a.get('authentication', '—')}")
    print(f"  SENDER:  {a.get('sender', '—')}")
    print(f"  INTEL:   {a.get('threat_intel', '—')}")
    print(f"  CONTENT: {a.get('content', '—')}")
    print(f"  VERDICT: {a.get('conclusion', '—')}")
    print(f"  SUMMARY: {result.get('reason', '—')}")

# ── Main ──────────────────────────────────────────────────────
def main():
    db = Database()
    prepare_db(db)

    emails = db.get_unique_emails()
    logger.info(f"Running Groq SOC analysis on {len(emails)} emails")

    for i, row in enumerate(emails, 1):
        filename = row["filename"]

        # Skip already analyzed
        if row.get("groq_verdict"):
            logger.info(f"[{i}/{len(emails)}] {filename} — already analyzed, skipping")
            continue

        print(f"\n[{i}/{len(emails)}] {filename}")
        print(f"  From:    {row['from_address']}")
        print(f"  Subject: {row['subject']}")
        print(f"  Analyzing...")

        body   = parser.get_body(filename, limit=500)
        result = analyze_with_groq(row, body)

        if not result:
            logger.warning(f"  Groq returned no result for {filename}")
            print("  Groq failed — skipping")
            print("-" * 60)
            time.sleep(5)
            continue

        # Print SOC report
        print_soc_report(result)

        # Save to database
        analysis_json = json.dumps(result.get("analysis", {}))

        db.cursor.execute("""
            UPDATE email_reports
            SET groq_verdict=%s, groq_confidence=%s,
                groq_risk_score=%s, groq_reason=%s, groq_analysis=%s,
                llm_verdict=%s, llm_confidence=%s,
                llm_risk_score=%s, llm_reason=%s
            WHERE id=%s
        """, (
            result.get("verdict"),
            result.get("confidence"),
            result.get("risk_score"),
            result.get("reason"),
            analysis_json,
            result.get("verdict"),
            result.get("confidence"),
            result.get("risk_score"),
            result.get("reason"),
            row["id"]
        ))
        db.conn.commit()

        logger.info(f"  Saved — {result['verdict'].upper()} {result['risk_score']}/100")
        print("-" * 60)

        # Wait between requests to avoid rate limit
        time.sleep(3)

    db.close()
    logger.info("Groq SOC analysis complete!")
    print("\nLLM analysis complete!")

if __name__ == "__main__":
    main()

