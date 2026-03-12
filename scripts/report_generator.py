# =============================================================
# scripts/report_generator.py
# Step 5: Generate a structured JSON scorecard report per email
# Output: reports/<filename>_report.json
# =============================================================
#step 5
import os
import sys
import json
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.database import Database
from utils.logger import get_logger

logger = get_logger("report_generator")

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")


# ── Ensure reports/ folder exists ────────────────────────────
def ensure_reports_dir() -> None:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    logger.info(f"Reports directory ready: {REPORTS_DIR}")


# ── Map score to severity label ───────────────────────────────
def score_to_severity(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    return "LOW"


# ── Map verdict to threat category ───────────────────────────
def verdict_to_category(verdict: str) -> str:
    return {
        "phishing": "Email Phishing Attack",
        "bec":      "Business Email Compromise (BEC)",
        "spam":     "Unsolicited Bulk Email (Spam)",
        "benign":   "Legitimate Email"
    }.get((verdict or "").lower(), "Unclassified")


# ── Determine authentication overall status ───────────────────
def auth_status(spf: str, dkim: str, dmarc: str) -> str:
    failures = []
    if spf in ["fail", "softfail"]:
        failures.append("SPF")
    if dkim in ["fail", "none"]:
        failures.append("DKIM")
    if dmarc in ["fail", "none"]:
        failures.append("DMARC")

    if not failures:
        return "PASS"
    elif len(failures) == 3:
        return "FAIL - All checks failed"
    return f"PARTIAL FAIL - {', '.join(failures)} failed"


# ── Build scorecard dict from DB row ─────────────────────────
def build_scorecard(row: dict) -> dict:

    # Parse rule reasons safely
    try:
        raw_reasons = row.get("rule_reasons") or "[]"
        top_reasons = json.loads(raw_reasons) if isinstance(raw_reasons, str) else list(raw_reasons)
    except Exception:
        top_reasons = []

    # Parse LLM analysis safely
    try:
        raw_analysis = row.get("groq_analysis") or "{}"
        llm_analysis = json.loads(raw_analysis) if isinstance(raw_analysis, str) else dict(raw_analysis)
    except Exception:
        llm_analysis = {}

    # Core fields
    verdict    = (row.get("final_verdict") or "unknown").lower()
    level      = (row.get("final_level")   or score_to_severity(int(row.get("final_score") or 0))).upper()
    score      = int(row.get("final_score")      or 0)
    rule_score = int(row.get("rule_score")        or 0)
    llm_score  = int(row.get("groq_risk_score")   or row.get("llm_risk_score") or 0)
    llm_source = (row.get("llm_source")           or "groq").upper()

    spf   = (row.get("spf")   or "none").lower()
    dkim  = (row.get("dkim")  or "none").lower()
    dmarc = (row.get("dmarc") or "none").lower()

    scorecard = {

        # ── Report Metadata ───────────────────────────────────
        "report_metadata": {
            "generated_at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "report_version": "1.0",
            "analyzer":       "Email Threat Analyzer — Atria Solutions"
        },

        # ── Email Identity ────────────────────────────────────
        "email_identity": {
            "filename":  row.get("filename", "unknown"),
            "from":      row.get("from_address", ""),
            "subject":   row.get("subject", ""),
            "domain":    row.get("sender_domain", ""),
            "sender_ip": row.get("sender_ip") or "unavailable"
        },

        # ── Final Verdict ─────────────────────────────────────
        "final_verdict": {
            "classification":  verdict.upper(),
            "threat_category": verdict_to_category(verdict),
            "risk_score":      score,
            "severity":        level,
            "risk_score_breakdown": {
                "rule_engine_score": rule_score,
                "llm_score":         llm_score,
                "llm_source":        llm_source,
                "formula":           "Final Score = (Rule Engine x 0.70) + (LLM x 0.30)"
            }
        },

        # ── Authentication Results ────────────────────────────
        "authentication": {
            "overall_status": auth_status(spf, dkim, dmarc),
            "spf":            spf.upper(),
            "dkim":           dkim.upper(),
            "dmarc":          dmarc.upper()
        },

        # ── Threat Intelligence ───────────────────────────────
        "threat_intelligence": {
            "abuse_ipdb": {
                "score":      int(row.get("abuse_score") or 0),
                "max_score":  100,
                "risk_level": score_to_severity(int(row.get("abuse_score") or 0))
            },
            "domain_age": {
                "days_since_registration": int(row.get("domain_age_days") or -1),
                "registered_on":           row.get("domain_registered") or "unknown",
                "note":                    "Domains under 180 days are considered high risk"
            },
            "ssl_certificate": row.get("ssl_info")                or "unavailable",
            "dnsbl_status":    row.get("dnsbl_listed")            or "clean",
            "otx_pulses":      int(row.get("otx_pulses")          or 0),
            "greynoise":       row.get("greynoise_classification") or "unknown",
            "urlhaus":         row.get("urlhaus_status")           or "clean",
            "threatfox":       row.get("threatfox_status")         or "clean",
            "pulsedive_risk":  row.get("pulsedive_risk")          or "unknown"
        },

        # ── Rule Engine Findings ──────────────────────────────
        "rule_engine_findings": {
            "total_flags": len(top_reasons),
            "flags":       top_reasons[:5]
        },

        # ── LLM Analysis ──────────────────────────────────────
        "llm_analysis": {
            "source":         llm_source,
            "summary":        row.get("groq_reason") or row.get("llm_reason") or "No LLM analysis available.",
            "authentication": llm_analysis.get("authentication", "Not analyzed"),
            "sender":         llm_analysis.get("sender",         "Not analyzed"),
            "threat_intel":   llm_analysis.get("threat_intel",   "Not analyzed"),
            "content":        llm_analysis.get("content",        "Not analyzed"),
            "conclusion":     llm_analysis.get("conclusion",     "Not analyzed")
        }
    }

    return scorecard


# ── Save scorecard to JSON file ───────────────────────────────
def save_scorecard(scorecard: dict) -> str:
    filename    = scorecard["email_identity"]["filename"]
    base_name   = os.path.splitext(filename)[0]
    output_path = os.path.join(REPORTS_DIR, f"{base_name}_report.json")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(scorecard, f, indent=2, ensure_ascii=False)

    return output_path


# ── Print summary to terminal ─────────────────────────────────
def print_summary(scorecard: dict) -> None:
    v  = scorecard["final_verdict"]
    a  = scorecard["authentication"]
    ti = scorecard["threat_intelligence"]
    rf = scorecard["rule_engine_findings"]

    print(f"  Classification : {v['classification']} — {v['threat_category']}")
    print(f"  Risk Score     : {v['risk_score']}/100  |  Severity: {v['severity']}")
    print(f"  Rule Engine    : {v['risk_score_breakdown']['rule_engine_score']}/100  |  LLM ({v['risk_score_breakdown']['llm_source']}): {v['risk_score_breakdown']['llm_score']}/100")
    print(f"  Authentication : {a['overall_status']}")
    print(f"  AbuseIPDB      : {ti['abuse_ipdb']['score']}/100  |  OTX Pulses: {ti['otx_pulses']}  |  DNSBL: {ti['dnsbl_status']}")
    if rf["flags"]:
        print(f"  Top Flags      : {' | '.join(rf['flags'][:3])}")
    print(f"  LLM Summary    : {scorecard['llm_analysis']['summary']}")


# ── Main ──────────────────────────────────────────────────────
def main():
    ensure_reports_dir()

    db     = Database()
    emails = db.get_unique_emails()

    logger.info(f"Generating reports for {len(emails)} emails")
    print(f"Report Generator — Processing {len(emails)} emails")
    print("=" * 60)

    success = 0
    failed  = 0

    for i, row in enumerate(emails, 1):
        filename = row.get("filename", f"email_{i}")
        print(f"\n[{i}/{len(emails)}] {filename}")
        print(f"  From    : {row.get('from_address', '')}")
        print(f"  Subject : {row.get('subject', '')}")

        try:
            scorecard   = build_scorecard(row)
            output_path = save_scorecard(scorecard)
            print_summary(scorecard)
            print(f"  Report  : {output_path}")
            logger.info(f"Report saved: {output_path}")
            success += 1
        except Exception as e:
            logger.error(f"Failed to generate report for {filename}: {e}")
            print(f"  ERROR   : {e}")
            failed += 1

        print("-" * 60)

    db.close()

    print(f"\nReport generation complete.")
    print(f"  Total processed : {len(emails)}")
    print(f"  Succeeded       : {success}")
    print(f"  Failed          : {failed}")
    print(f"  Output folder   : {REPORTS_DIR}")
    logger.info(f"Report generation complete — {success} success, {failed} failed")


if __name__ == "__main__":
    main()