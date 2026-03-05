
import os
import re
import email
from email import policy
from config.settings import LEGIT_FOLDER, SAMPLE_FOLDER
from utils.logger import get_logger

logger = get_logger("email_parser")

class EmailParser:
    """Reads .eml files and extracts headers, body, and IP."""

    def get_folder(self, filename: str) -> str:
        """Returns the correct folder based on filename prefix."""
        return SAMPLE_FOLDER if filename.startswith("sample") else LEGIT_FOLDER

    def get_body(self, filename: str, limit: int = 500) -> str:
        """Extracts plain text body from an .eml file."""
        filepath = os.path.join(self.get_folder(filename), filename)
        try:
            with open(filepath, "rb") as f:
                msg = email.message_from_binary_file(f, policy=policy.default)
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        try:
                            body += part.get_content()
                        except:
                            pass
            else:
                try:
                    body = msg.get_content()
                except:
                    body = ""
            return body[:limit]
        except Exception as e:
            logger.error(f"Failed to read body from {filename}: {e}")
            return ""

    def extract_ip(self, filename: str) -> str:
        """Extracts the sender's real IP from email headers."""
        filepath = os.path.join(self.get_folder(filename), filename)
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            patterns = [
                r"Received:.*?\[(\d+\.\d+\.\d+\.\d+)\]",
                r"Received: from.*?(\d+\.\d+\.\d+\.\d+)",
                r"X-Originating-IP: (\d+\.\d+\.\d+\.\d+)",
                r"X-Sender-IP: (\d+\.\d+\.\d+\.\d+)"
            ]
            for pattern in patterns:
                ips = re.findall(pattern, content)
                for ip in ips:
                    if not any(ip.startswith(p) for p in ["127.", "10.", "192.168."]):
                        return ip
        except Exception as e:
            logger.error(f"Failed to extract IP from {filename}: {e}")
        return None

    def parse_auth_results(self, auth_header: str) -> dict:
        """Parses SPF, DKIM, DMARC from Authentication-Results header."""
        results = {"spf": "none", "dkim": "none", "dmarc": "none"}
        if not auth_header:
            return results
        for part in auth_header.split(";"):
            part = part.strip().lower()
            if "spf=" in part:
                results["spf"] = part.split("spf=")[1].split()[0]
            if "dkim=" in part:
                results["dkim"] = part.split("dkim=")[1].split()[0]
            if "dmarc=" in part:
                results["dmarc"] = part.split("dmarc=")[1].split()[0]
        return results
def extract_domain(self, from_address: str) -> str:
    """Extracts ROOT domain from a From address."""
    if from_address and "@" in from_address:
        full_domain = from_address.split("@")[-1].strip(">").strip()
        # Extract root domain (e.g. discover.pinterest.com → pinterest.com)
        parts = full_domain.split(".")
        if len(parts) >= 2:
            return f"{parts[-2]}.{parts[-1]}"
        return full_domain
    return "unknown"