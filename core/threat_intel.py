import ssl
import socket
import dns.resolver
import requests
from datetime import datetime
from config.settings import (
    ABUSEIPDB_KEY, ALIENVAULT_KEY, PULSEDIVE_KEY, DNSBL_SERVERS
)
from utils.logger import get_logger

logger = get_logger("threat_intel")

class ThreatIntel:
    """Queries multiple threat intelligence sources for IPs and domains."""

    def check_abuseipdb(self, ip: str) -> int:
        """Returns abuse confidence score 0-100. Higher = more malicious."""
        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=10
            )
            return response.json()["data"]["abuseConfidenceScore"]
        except Exception as e:
            logger.warning(f"AbuseIPDB failed for {ip}: {e}")
            return -1

    def check_alienvault(self, ip: str) -> int:
        """Returns OTX pulse count — how many threat reports mention this IP."""
        try:
            response = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": ALIENVAULT_KEY},
                timeout=10
            )
            return response.json().get("pulse_info", {}).get("count", 0)
        except Exception as e:
            logger.warning(f"AlienVault OTX failed for {ip}: {e}")
            return -1

    def check_greynoise(self, ip: str) -> dict:
        """Returns GreyNoise classification — noise, riot, or malicious."""
        try:
            response = requests.get(
                f"https://api.greynoise.io/v3/community/{ip}",
                timeout=10
            )
            data = response.json()
            return {
                "noise":          data.get("noise", False),
                "riot":           data.get("riot", False),
                "classification": data.get("classification", "unknown")
            }
        except Exception as e:
            logger.warning(f"GreyNoise failed for {ip}: {e}")
            return {"noise": False, "riot": False, "classification": "unknown"}

    def check_urlhaus(self, domain: str) -> str:
        """Checks if domain has been used to distribute malware."""
        try:
            response = requests.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": domain},
                timeout=10
            )
            data       = response.json()
            status     = data.get("query_status", "")
            urls_count = len(data.get("urls", []))
            if status == "is_host":
                return f"Found {urls_count} malicious URLs"
            return "clean"
        except Exception as e:
            logger.warning(f"URLhaus failed for {domain}: {e}")
            return "unknown"

    def check_threatfox(self, ioc: str) -> str:
        """Checks if IP or domain is associated with known malware."""
        try:
            response = requests.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": ioc},
                timeout=10
            )
            data = response.json()
            if data.get("query_status") == "ok":
                iocs = data.get("data", [])
                if iocs:
                    malware = iocs[0].get("malware_printable", "unknown")
                    return f"Malware: {malware}"
            return "clean"
        except Exception as e:
            logger.warning(f"ThreatFox failed for {ioc}: {e}")
            return "unknown"

    def check_pulsedive(self, indicator: str) -> str:
        """Returns Pulsedive risk level: none/low/medium/high/critical."""
        try:
            response = requests.get(
                "https://pulsedive.com/api/info.php",
                params={"indicator": indicator, "pretty": 1, "key": PULSEDIVE_KEY},
                timeout=10
            )
            return response.json().get("risk", "unknown")
        except Exception as e:
            logger.warning(f"Pulsedive failed for {indicator}: {e}")
            return "unknown"

    def check_dnsbl(self, ip: str) -> list:
        """Checks IP against DNSBL blacklists."""
        reversed_ip = ".".join(reversed(ip.split(".")))
        listed_on   = []
        for bl in DNSBL_SERVERS:
            try:
                dns.resolver.resolve(f"{reversed_ip}.{bl}", "A")
                listed_on.append(bl)
            except:
                pass
        return listed_on

    def check_domain_age(self, domain: str) -> tuple[int, str]:
        """Returns (age_in_days, registration_date_string) for a domain."""
        try:
            response = requests.get(
                f"https://rdap.org/domain/{domain}",
                timeout=10
            )
            for event in response.json().get("events", []):
                if event.get("eventAction") == "registration":
                    reg_date  = event.get("eventDate", "")
                    created   = datetime.strptime(reg_date[:10], "%Y-%m-%d")
                    age_days  = (datetime.now() - created).days
                    return age_days, created.strftime("%B %d, %Y")
        except Exception as e:
            logger.warning(f"RDAP failed for {domain}: {e}")
        return -1, "unknown"

    def check_ssl(self, domain: str) -> str:
        """Returns SSL certificate issuer and expiry date."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert    = ssock.getpeercert()
                    issuer  = dict(x[0] for x in cert.get("issuer", []))
                    expires = cert.get("notAfter", "unknown")
                    org     = issuer.get("organizationName", "unknown")
                    return f"Issuer: {org} | Expires: {expires}"
        except Exception as e:
            logger.warning(f"SSL check failed for {domain}: {e}")
            return "unknown"

    def check_all(self, ip: str | None, domain: str) -> dict:
        """
        Runs all threat intel checks for an IP and domain.
        Returns a single dictionary with all results combined.
        """
        results = {
            "ip":                ip,
            "abuse_score":       -1,
            "otx_pulses":        -1,
            "greynoise":         "unknown",
            "dnsbl":             "[]",
            "threatfox":         "clean | clean",
            "pulsedive":         "unknown | unknown",
            "urlhaus":           "unknown",
            "domain_age":        -1,
            "domain_registered": "unknown",
            "ssl_info":          "unknown"
        }

        # IP-based checks
        if ip:
            abuse         = self.check_abuseipdb(ip)
            otx           = self.check_alienvault(ip)
            gn            = self.check_greynoise(ip)
            dnsbl         = self.check_dnsbl(ip)
            threatfox_ip  = self.check_threatfox(ip)
            pulsedive_ip  = self.check_pulsedive(ip)

            results["abuse_score"] = abuse
            results["otx_pulses"]  = otx
            results["greynoise"]   = gn["classification"]
            results["dnsbl"]       = str(dnsbl)

            logger.info(f"  AbuseIPDB: {abuse}/100 | OTX: {otx} | GreyNoise: {gn['classification']}")
            logger.info(f"  DNSBL: {dnsbl if dnsbl else 'clean'} | ThreatFox: {threatfox_ip} | Pulsedive IP: {pulsedive_ip}")
        else:
            threatfox_ip = "unknown"
            pulsedive_ip = "unknown"
            logger.warning("  No IP found in email headers")

        # Domain-based checks
        urlhaus          = self.check_urlhaus(domain)
        threatfox_dom    = self.check_threatfox(domain)
        pulsedive_dom    = self.check_pulsedive(domain)
        age, reg_date    = self.check_domain_age(domain)
        ssl_info         = self.check_ssl(domain)

        results["urlhaus"]           = urlhaus
        results["threatfox"]         = f"IP: {threatfox_ip} | Domain: {threatfox_dom}"
        results["pulsedive"]         = f"IP: {pulsedive_ip} | Domain: {pulsedive_dom}"
        results["domain_age"]        = age
        results["domain_registered"] = reg_date
        results["ssl_info"]          = ssl_info

        logger.info(f"  URLhaus: {urlhaus} | Domain Age: {age} days ({reg_date})")
        logger.info(f"  SSL: {ssl_info}")

        return results