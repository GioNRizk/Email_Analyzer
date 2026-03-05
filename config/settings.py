# =============================================================
# config/settings.py
# Central configuration — all constants and settings live here
# Change once, applies everywhere in the project
# =============================================================

import os
from dotenv import load_dotenv

load_dotenv()

# ── Database ──────────────────────────────────────────────────
DB_HOST     = os.getenv("DB_HOST")
DB_USER     = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME     = os.getenv("DB_NAME")
DB_PORT     = int(os.getenv("DB_PORT", 3306))

# ── API Keys ──────────────────────────────────────────────────
ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_API_KEY")
ALIENVAULT_KEY = os.getenv("ALIENVAULT_API_KEY")
PULSEDIVE_KEY  = os.getenv("PULSEDIVE_API_KEY")

# ── Email Folders ─────────────────────────────────────────────
LEGIT_FOLDER   = "eml_downloads"
SAMPLE_FOLDER  = "eml_downloads1"

# ── LLM Settings ─────────────────────────────────────────────
LLM_MODEL      = "phi3"
LLM_TIMEOUT    = 180
LLM_URL        = "http://localhost:11434/api/generate"
LLM_BODY_LIMIT = 500

# ── Risk Scoring Thresholds ───────────────────────────────────
CRITICAL_THRESHOLD = 75
HIGH_THRESHOLD     = 55
MEDIUM_THRESHOLD   = 30

# ── DNSBL Blacklist Servers ───────────────────────────────────
DNSBL_SERVERS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org"
]

# ── Whitelisted Trusted Domains ───────────────────────────────
# Emails from these domains skip aggressive scoring
WHITELIST = [
    "linkedin.com",
    "google.com",
    "zoom.us",
    "medium.com",
    "coursera.org",
    "learn.coursera.org",
    "m.learn.coursera.org",
    "pinterest.com",
    "discover.pinterest.com",
    "gulftalent.com",
    "atriasolutions.com",
    "e.zoom.us",
    "gmatpoint.com"
]

# ── Brand Impersonation Map ───────────────────────────────────
# If brand keyword appears in FROM but domain doesn't match → phishing
TRUSTED_BRANDS = {
    "paypal":    "paypal.com",
    "microsoft": "microsoft.com",
    "apple":     "apple.com",
    "amazon":    "amazon.com",
    "netflix":   "netflix.com",
    "coinbase":  "coinbase.com",
    "facebook":  "facebook.com",
    "instagram": "instagram.com",
    "dhl":       "dhl.com",
    "fedex":     "fedex.com",
    "chase":     "chase.com",
    "ftx":       "ftx.com",
    "binance":   "binance.com",
    "bradesco":  "bradesco.com.br",
    "mashreq":   "mashreq.com",
}

# ── Suspicious TLDs ───────────────────────────────────────────
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".online",
    ".site", ".tk", ".ml", ".ga", ".cf"
]

# ── Urgent/Phishing Keywords ──────────────────────────────────
URGENT_KEYWORDS = [
    "urgent", "suspended", "blocked", "verify", "confirm",
    "unusual activity", "unauthorized", "expiring", "expire",
    "withdraw", "authorized", "security alert", "action required",
    "immediately", "case#", "winner", "congratulations",
    "prize", "limited time", "account blocked", "signin activity"
]