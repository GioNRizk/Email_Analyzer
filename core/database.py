import mysql.connector
from config.settings import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_PORT
from utils.logger import get_logger

logger = get_logger("database")

class Database:
    """Manages MySQL connection and all email_reports queries."""

    def __init__(self):
        self.conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            port=DB_PORT
        )
        self.cursor = self.conn.cursor(dictionary=True)
        logger.info("Connected to database successfully")

    def add_columns(self, columns: list) -> None:
        """Adds new columns to the table if they don't exist yet."""
        for col in columns:
            try:
                self.cursor.execute(col)
                self.conn.commit()
            except:
                pass

    def get_unique_emails(self) -> list:
        """Fetches the latest version of each unique email."""
        self.cursor.execute("""
            SELECT * FROM email_reports
            WHERE id IN (
                SELECT MAX(id) FROM email_reports GROUP BY filename
            )
            ORDER BY filename
        """)
        return self.cursor.fetchall()

    def update_reputation(self, id: int, data: dict) -> None:
        """Saves reputation check results for one email."""
        self.cursor.execute("""
            UPDATE email_reports
            SET sender_ip=%s, abuse_score=%s, dnsbl_listed=%s,
                domain_age_days=%s, domain_registered=%s, ssl_info=%s,
                otx_pulses=%s, greynoise_classification=%s,
                urlhaus_status=%s, threatfox_status=%s, pulsedive_risk=%s
            WHERE id=%s
        """, (
            data["ip"], data["abuse_score"], data["dnsbl"],
            data["domain_age"], data["domain_registered"], data["ssl_info"],
            data["otx_pulses"], data["greynoise"],
            data["urlhaus"], data["threatfox"], data["pulsedive"],
            id
        ))
        self.conn.commit()

    def update_llm_result(self, id: int, data: dict) -> None:
        """Saves LLM analysis results for one email."""
        self.cursor.execute("""
            UPDATE email_reports
            SET llm_verdict=%s, llm_confidence=%s,
                llm_risk_score=%s, llm_reason=%s
            WHERE id=%s
        """, (
            data["verdict"], data["confidence"],
            data["risk_score"], data["reason"],
            id
        ))
        self.conn.commit()

    def update_final_verdict(self, id: int, data: dict) -> None:
        """Saves final combined verdict for one email."""
        self.cursor.execute("""
            UPDATE email_reports
            SET rule_score=%s, rule_level=%s, rule_reasons=%s,
                final_verdict=%s, final_score=%s, final_level=%s
            WHERE id=%s
        """, (
            data["rule_score"], data["rule_level"], data["rule_reasons"],
            data["final_verdict"], data["final_score"], data["final_level"],
            id
        ))
        self.conn.commit()

    def close(self) -> None:
        """Closes the database connection."""
        self.cursor.close()
        self.conn.close()
        logger.info("Database connection closed")