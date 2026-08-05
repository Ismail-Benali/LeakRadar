"""Main scheduling and orchestrator for LeakRadar."""
import time
from datetime import datetime

import schedule
from loguru import logger

from src.alerting import AlertEngine
from src.breach_api import HaveIBeenPwnedAPI
from src.config import config
from src.models import BreachCheckResult
from src.storage import BreachStorage


class LeakRadar:
    """Main LeakRadar orchestrator."""

    def __init__(self):
        self.api = HaveIBeenPwnedAPI(config.hibp_api_key, config.hibp_api_url)
        self.storage = BreachStorage(config.database_url)
        self.alerter = AlertEngine()

        logger.info("LeakRadar initialized")

    def scan_email(self, email: str) -> None:
        """Scan a single email address for breaches."""
        logger.info(f"Starting scan for {email}")

        try:
            breaches = self.api.get_breached_account(email)
            new_breaches = self.storage.save_breaches(email, breaches)

            result = BreachCheckResult(
                email=email,
                breaches=new_breaches,
                is_new=len(new_breaches) > 0,
            )

            self.storage.save_check_result(result)

            if result.is_new:
                logger.warning(f"Found {len(new_breaches)} new breaches for {email}")
                self.alerter.send_alerts(result)
            else:
                logger.info(f"No new breaches found for {email}")

        except Exception as e:
            logger.error(f"Error scanning {email}: {e}")

    def scan_all_emails(self) -> None:
        """Scan all configured email addresses."""
        logger.info("=" * 60)
        logger.info(f"Starting scan cycle at {datetime.now()}")
        logger.info("=" * 60)

        for email in config.target_emails:
            email = email.strip()
            if email:
                self.scan_email(email)
                time.sleep(2)

        logger.info("=" * 60)
        logger.info("Scan cycle completed")
        logger.info("=" * 60)

    def run_scheduled(self) -> None:
        """Run scheduled monitoring in a loop."""
        logger.info(
            f"Starting scheduled monitoring every {config.scan_interval_hours} hours"
        )

        self.scan_all_emails()
        schedule.every(config.scan_interval_hours).hours.do(self.scan_all_emails)

        try:
            while True:
                schedule.run_pending()
                time.sleep(60)
        except KeyboardInterrupt:
            logger.info("Shutting down LeakRadar")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            raise
