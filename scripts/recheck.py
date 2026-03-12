import os
import sys
import re
import json
#step 5
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.database import Database
from config.settings import (
    WHITELIST, TRUSTED_BRANDS, SUSPICIOUS_TLDS,
    URGENT_KEYWORDS, CRITICAL_THRESHOLD,
    HIGH_THRESHOLD, MEDIUM_THRESHOLD
)
from utils.logger import get_logger

logger = get_logger("recheck")

# ── Add columns if missing ────────────────────────────────────
def prepare_db(db: Database) -> None:
    db.add_columns([
        "ALTER TABLE email_reports ADD COLUMN rule_score INT",
        "ALTER TABLE email_reports ADD COLUMN rule_level VARCHAR(20)",
        "ALTER TABLE email_reports ADD COLUMN rule_reasons TEXT",
        "ALTER TABLE email_reports ADD COLUMN final_verdict VARCHAR(50)",
        "ALTER TABLE email_reports ADD COLUMN final_score INT",
        "ALTER TABLE email_reports ADD COLUMN final_level VARCHAR(20)",
    ])

# ── Rule-Based Scoring Engine ─────────────────────────────────
def rule_based_score(row: dict) -> tuple:
    score   = 0
    reasons = []

    from_address  = (row.get("from_address")   or "").lower()
    subject       = (row.get("subject")        or "").lower()
    spf           = (row.get("spf")            or "none").lower()
    dkim          = (row.get("dkim")           or "none").lower()
    dmarc         = (row.get("dmarc")          or "none").lower()
    abuse_score   = int(row.get("abuse_score")     or 0)
    domain_age    = int(row.get("domain_age_days") or -1)
    dnsbl         = (row.get("dnsbl_listed")   or "")
    ssl_info      = (row.get("ssl_info")       or "")
    sender_domain = (row.get("sender_domain")  or "").lower()

    # ── Whitelist ─────────────────────────────────────────
    for trusted in WHITELIST:
        if trusted in sender_domain:
            return 0, "LOW", "benign", [f"Whitelisted: {sender_domain}"]

    # ── Authentication ────────────────────────────────────
    if spf == "fail":
        score += 25
        reasons.append("SPF failed")
    elif spf in ["softfail", "temperror", "permerror"]:
        score += 10
        reasons.append(f"SPF {spf}")

    if dkim == "fail":
        score += 25
        reasons.append("DKIM failed")
    elif dkim == "none":
        score += 10
        reasons.append("DKIM missing")

    if dmarc == "fail":
        score += 25
        reasons.append("DMARC failed")
    elif dmarc in ["none", "permerror"]:
        score += 10
        reasons.append(f"DMARC {dmarc}")

    # ── IP Reputation ─────────────────────────────────────
    if abuse_score > 80:
        score += 30
        reasons.append(f"AbuseIPDB critical ({abuse_score}/100)")
    elif abuse_score > 50:
        score += 20
        reasons.append(f"AbuseIPDB high ({abuse_score}/100)")
    elif abuse_score > 20:
        score += 10
        reasons.append(f"AbuseIPDB medium ({abuse_score}/100)")

    if dnsbl and dnsbl not in ["[]", "", "clean"]:
        score += 20
        reasons.append(f"Blacklisted: {dnsbl}")

    # ── Domain Age ────────────────────────────────────────
    if domain_age != -1:
        if domain_age < 30:
            score += 35
            reasons.append(f"Very new domain ({domain_age} days)")
        elif domain_age < 180:
            score += 15
            reasons.append(f"New domain ({domain_age} days)")

    # ── Brand Impersonation ───────────────────────────────
    for brand, official_domain in TRUSTED_BRANDS.items():
        if brand in from_address:
            if official_domain not in sender_domain:
                score += 40
                reasons.append(f"Brand impersonation: {brand} → {sender_domain}")
                break

    # ── Coinbase space trick ──────────────────────────────
    if "c o i n b a s e" in from_address or "coinbase" in from_address:
        if "coinbase.com" not in sender_domain:
            score += 45
            reasons.append(f"Coinbase impersonation from {sender_domain}")

    # ── Urgent Keywords ───────────────────────────────────
    matched = [kw for kw in URGENT_KEYWORDS if kw in subject]
    if matched:
        score += min(len(matched) * 8, 25)
        reasons.append(f"Urgent keywords: {matched}")

    # ── Suspicious TLDs ───────────────────────────────────
    for tld in SUSPICIOUS_TLDS:
        if sender_domain.endswith(tld):
            score += 20
            reasons.append(f"Suspicious TLD: {tld}")
            break

    # ── Suspicious Domain Pattern ─────────────────────────
    if re.search(r"\d{3,}", sender_domain) or sender_domain.count("-") > 2:
        score += 15
        reasons.append(f"Suspicious domain pattern: {sender_domain}")

    # ── No SSL ────────────────────────────────────────────
    if not ssl_info or ssl_info == "unknown":
        score += 5
        reasons.append("No SSL certificate")

    # ── Cap at 100 ────────────────────────────────────────
    score = max(0, min(score, 100))

    # ── Assign level ──────────────────────────────────────
    if score >= CRITICAL_THRESHOLD:
        level   = "CRITICAL"
        verdict = "phishing"
    elif score >= HIGH_THRESHOLD:
        level   = "HIGH"
        verdict = "phishing"
    elif score >= MEDIUM_THRESHOLD:
        level   = "MEDIUM"
        verdict = "spam"
    else:
        level   = "LOW"
        verdict = "benign"

    return score, level, verdict, reasons

# ── Combine rule + Groq → final verdict ──────────────────────
def combine_scores(rule_score: int, groq_score: int,
                   rule_verdict: str, groq_verdict: str,
                   groq_confidence: str) -> tuple:
    """
    Rule engine: 70% weight
    Groq LLM:    30% weight
    """
    final_score = int((rule_score * 0.7) + (groq_score * 0.3))
    final_score = max(0, min(final_score, 100))

    # Determine final level
    if final_score >= CRITICAL_THRESHOLD:
        final_level = "CRITICAL"
    elif final_score >= HIGH_THRESHOLD:
        final_level = "HIGH"
    elif final_score >= MEDIUM_THRESHOLD:
        final_level = "MEDIUM"
    else:
        final_level = "LOW"

    # Determine final verdict
    # Groq BEC with high confidence overrides rule verdict
    if groq_verdict == "bec" and groq_confidence == "high":
        final_verdict = "bec"
    elif final_score >= MEDIUM_THRESHOLD:
        # If either says phishing → phishing wins
        if "phishing" in [rule_verdict, groq_verdict]:
            final_verdict = "phishing"
        elif "bec" in [rule_verdict, groq_verdict]:
            final_verdict = "bec"
        else:
            final_verdict = "spam"
    else:
        final_verdict = "benign"

    return final_score, final_level, final_verdict

# ── Main ──────────────────────────────────────────────────────
def main():
    db = Database()
    prepare_db(db)

    emails = db.get_unique_emails()
    logger.info(f"Running hybrid scoring on {len(emails)} emails")
    print("=" * 60)

    for i, row in enumerate(emails, 1):
        filename = row["filename"]
        print(f"\n[{i}/{len(emails)}] {filename}")
        print(f"  From:    {row['from_address']}")
        print(f"  Subject: {row['subject']}")

        # ── Rule-based score ──────────────────────────────
        rule_score, rule_level, rule_verdict, reasons = rule_based_score(row)

        # ── Get Groq score ────────────────────────────────
        groq_score      = int(row.get("groq_risk_score")  or 0)
        groq_verdict    = (row.get("groq_verdict")        or "unknown").lower()
        groq_confidence = (row.get("groq_confidence")     or "low").lower()

        # ── Combine ───────────────────────────────────────
        final_score, final_level, final_verdict = combine_scores(
            rule_score, groq_score,
            rule_verdict, groq_verdict,
            groq_confidence
        )

        # ── Print result ──────────────────────────────────
        emoji = {
            "phishing": "🚨",
            "bec":      "⚠️",
            "spam":     "📢",
            "benign":   "✅"
        }.get(final_verdict, "❓")

        print(f"  Rule:  {rule_score}/100 ({rule_level}) → {rule_verdict}")
        print(f"  Groq:  {groq_score}/100 → {groq_verdict}")
        print(f"  {emoji} FINAL: {final_verdict.upper()} | {final_score}/100 | {final_level}")
        print(f"  Reasons: {' | '.join(reasons[:3])}")

        # ── Save to database ──────────────────────────────
        db.update_final_verdict(row["id"], {
            "rule_score":    rule_score,
            "rule_level":    rule_level,
            "rule_reasons":  json.dumps(reasons),
            "final_verdict": final_verdict,
            "final_score":   final_score,
            "final_level":   final_level
        })

        logger.info(f"  Saved — {final_verdict.upper()} {final_score}/100 {final_level}")
        print("-" * 60)

    db.close()
    logger.info("Hybrid scoring complete!")
    print("\nRecheck complete!")

if __name__ == "__main__":
    main()