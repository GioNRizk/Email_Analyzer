# =============================================================
# scripts/report_generator.py
# Step 5: Generate a JSON scorecard report per email
# Output: reports/<filename>.json
# =============================================================

import os
import sys
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.database import Database
from utils.logger import get_logger

logger = get_logger("report_generator")

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")


# ── Ensure reports/ folder exists ────────────────────────────
def ensure_reports_dir() -> None:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    logger.info(f"Reports directory: {REPORTS_DIR}")


# ── Level emoji ───────────────────────────────────────────────
def level_emoji(level: str) -> str:
    return {
        "CRITICAL": "🔴",
        "HIGH":     "🟠",
        "MEDIUM":   "🟡",
        "LOW":      "🟢"
    }.get((level or "").upper(), "⚪")


# ── Verdict emoji ─────────────────────────────────────────────
def verdict_emoji(verdict: str) -> str:
    return {
        "phishing": "🚨",
        "bec":      "⚠️",
        "spam":     "📢",
        "benign":   "✅"
    }.get((verdict or "").lower(), "❓")


# ── Build scorecard dict from DB row ─────────────────────────
def build_scorecard(row: dict) -> dict:
    # Parse rule reasons safely
    try:
        raw_reasons = row.get("rule_reasons") or "[]"
        if isinstance(raw_reasons, str):
            top_reasons = json.loads(raw_reasons)
        else:
            top_reasons = list(raw_reasons)
    except Exception:
        top_reasons = []

    # Parse groq analysis safely
    try:
        raw_analysis = row.get("groq_analysis") or "{}"
        if isinstance(raw_analysis, str):
            llm_analysis = json.loads(raw_analysis)
        else:
            llm_analysis = dict(raw_analysis)
    except Exception:
        llm_analysis = {}

    verdict  = (row.get("final_verdict") or "unknown").lower()
    level    = (row.get("final_level")   or "LOW").upper()
    score    = int(row.get("final_score")    or 0)
    rule_score = int(row.get("rule_score")   or 0)
    llm_score  = int(row.get("groq_risk_score") or row.get("llm_risk_score") or 0)
    llm_source = row.get("llm_source") or "groq"

    scorecard = {
        "email":   row.get("filename", "unknown"),
        "from":    row.get("from_address", ""),
        "subject": row.get("subject", ""),

        "verdict": verdict.upper(),
        "verdict_emoji": verdict_emoji(verdict),
        "final_score": score,
        "level": level,
        "level_emoji": level_emoji(level),

        "scores": {
            "rule_engine": rule_score,
            "llm":         llm_score,
            "llm_source":  llm_source,
            "formula":     "Final = (Rule × 0.7) + (LLM × 0.3)"
        },

        "authentication": {
            "spf":   row.get("spf")   or "none",
            "dkim":  row.get("dkim")  or "none",
            "dmarc": row.get("dmarc") or "none"
        },

        "threat_intel": {
            "sender_ip":              row.get("sender_ip")               or "unknown",
            "abuse_ipdb":             int(row.get("abuse_score")         or 0),
            "dnsbl_listed":           row.get("dnsbl_listed")            or "clean",
            "domain_age_days":        int(row.get("domain_age_days")     or -1),
            "domain_registered":      row.get("domain_registered")       or "unknown",
            "ssl":                    row.get("ssl_info")                or "unknown",
            "otx_pulses":             int(row.get("otx_pulses")          or 0),
            "greynoise":              row.get("greynoise_classification") or "unknown",
            "urlhaus":                row.get("urlhaus_status")           or "clean",
            "threatfox":              row.get("threatfox_status")         or "clean",
            "pulsedive_risk":         row.get("pulsedive_risk")          or "unknown"
        },

        "top_reasons": top_reasons[:5],  # max 5 reasons

        "llm_summary": row.get("groq_reason") or row.get("llm_reason") or "No LLM analysis available.",

        "llm_analysis": {
            "authentication": llm_analysis.get("authentication", "—"),
            "sender":         llm_analysis.get("sender",         "—"),
            "threat_intel":   llm_analysis.get("threat_intel",   "—"),
            "content":        llm_analysis.get("content",        "—"),
            "conclusion":     llm_analysis.get("conclusion",     "—")
        }
    }

    return scorecard


# ── Save scorecard to JSON file ───────────────────────────────
def save_scorecard(scorecard: dict) -> str:
    base_name   = os.path.splitext(scorecard["email"])[0]  # remove .eml
    output_path = os.path.join(REPORTS_DIR, f"{base_name}_report.json")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(scorecard, f, indent=2, ensure_ascii=False)

    return output_path


# ── Print summary to terminal ─────────────────────────────────
def print_summary(scorecard: dict) -> None:
    v = scorecard["verdict_emoji"]
    l = scorecard["level_emoji"]
    print(f"  {v} {scorecard['verdict']} | {scorecard['final_score']}/100 | {l} {scorecard['level']}")
    print(f"  Rule: {scorecard['scores']['rule_engine']}/100 | LLM ({scorecard['scores']['llm_source']}): {scorecard['scores']['llm']}/100")
    print(f"  SPF: {scorecard['authentication']['spf']} | DKIM: {scorecard['authentication']['dkim']} | DMARC: {scorecard['authentication']['dmarc']}")
    if scorecard["top_reasons"]:
        print(f"  Reasons: {' | '.join(scorecard['top_reasons'][:3])}")
    print(f"  LLM: {scorecard['llm_summary']}")


# ── Main ──────────────────────────────────────────────────────
def main():
    ensure_reports_dir()

    db     = Database()
    emails = db.get_unique_emails()

    logger.info(f"Generating reports for {len(emails)} emails")
    print(f"Generating JSON scorecards for {len(emails)} emails")
    print("=" * 60)

    success = 0
    failed  = 0

    for i, row in enumerate(emails, 1):
        filename = row.get("filename", f"email_{i}")
        print(f"\n[{i}/{len(emails)}] {filename}")
        print(f"  From:    {row.get('from_address', '')}")
        print(f"  Subject: {row.get('subject', '')}")

        try:
            scorecard   = build_scorecard(row)
            output_path = save_scorecard(scorecard)
            print_summary(scorecard)
            print(f"  💾 Saved → {output_path}")
            logger.info(f"Report saved: {output_path}")
            success += 1
        except Exception as e:
            logger.error(f"Failed to generate report for {filename}: {e}")
            print(f"  ❌ Failed: {e}")
            failed += 1

        print("-" * 60)

    db.close()

    print(f"\n✅ Done! {success} reports generated, {failed} failed.")
    print(f"📁 Reports saved to: {REPORTS_DIR}")
    logger.info(f"Report generation complete — {success} success, {failed} failed")


if __name__ == "__main__":
    main()