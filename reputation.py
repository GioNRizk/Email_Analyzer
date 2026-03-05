from core.database import Database
from core.email_parser import EmailParser
from core.threat_intel import ThreatIntel
from utils.logger import get_logger
import os
from dotenv import load_dotenv
logger = get_logger("reputation")

# ── Initialize components ─────────────────────────────────────
db     = Database()
parser = EmailParser()
intel  = ThreatIntel()

# ── Add new columns to database ───────────────────────────────
db.add_columns([
    "ALTER TABLE email_reports ADD COLUMN sender_ip VARCHAR(50)",
    "ALTER TABLE email_reports ADD COLUMN abuse_score INT",
    "ALTER TABLE email_reports ADD COLUMN dnsbl_listed TEXT",
    "ALTER TABLE email_reports ADD COLUMN domain_age_days INT",
    "ALTER TABLE email_reports ADD COLUMN domain_registered TEXT",
    "ALTER TABLE email_reports ADD COLUMN ssl_info TEXT",
    "ALTER TABLE email_reports ADD COLUMN otx_pulses INT",
    "ALTER TABLE email_reports ADD COLUMN greynoise_classification VARCHAR(50)",
    "ALTER TABLE email_reports ADD COLUMN urlhaus_status TEXT",
    "ALTER TABLE email_reports ADD COLUMN threatfox_status TEXT",
    "ALTER TABLE email_reports ADD COLUMN pulsedive_risk VARCHAR(50)",
])

# ── Process each email ────────────────────────────────────────
emails = db.get_unique_emails()
logger.info(f"Processing {len(emails)} emails with 6 threat intel sources")
print("=" * 60)

for i, row in enumerate(emails, 1):
    filename = row["filename"]
    domain   = row["sender_domain"]

    logger.info(f"[{i}/{len(emails)}] {filename} — {row['from_address']}")

    # Extract IP and run all checks
    ip      = parser.extract_ip(filename)
    results = intel.check_all(ip, domain)

    # Save to database
    db.update_reputation(row["id"], results)
    logger.info(f"  ✅ Saved to database")
    print("-" * 60)

# ── Cleanup ───────────────────────────────────────────────────
db.close()
logger.info("✅ Reputation checks complete!")