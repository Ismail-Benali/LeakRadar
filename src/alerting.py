"""Multi-channel alerting engine (Telegram, Discord, Email)."""
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List

import requests
from loguru import logger

from src.config import config
from src.models import Breach, BreachCheckResult
from src.normalizer import DataNormalizer

SEVERITY_EMOJI = {
    "critical": "\U0001F534",
    "high": "\U0001F7E0",
    "medium": "\U0001F7E1",
    "low": "\U0001F7E2",
}


class AlertEngine:
    """Send breach alerts across multiple channels."""

    def __init__(self):
        self.telegram_enabled = bool(config.telegram_bot_token and config.telegram_chat_id)
        self.discord_enabled = bool(config.discord_webhook_url)
        self.email_enabled = bool(config.smtp_server and config.smtp_username)

    def send_alerts(self, result: BreachCheckResult) -> None:
        """Send alerts via all configured channels."""
        if not result.is_new:
            logger.info("No new breaches, skipping alerts")
            return

        breaches = result.breaches
        logger.info(f"Sending alerts for {len(breaches)} new breaches")

        if self.telegram_enabled:
            try:
                self._send_telegram_alert(result.email, breaches)
                logger.info("Telegram alert sent successfully")
            except Exception as e:
                logger.error(f"Failed to send Telegram alert: {e}")

        if self.discord_enabled:
            try:
                self._send_discord_alert(result.email, breaches)
                logger.info("Discord alert sent successfully")
            except Exception as e:
                logger.error(f"Failed to send Discord alert: {e}")

        if self.email_enabled:
            try:
                self._send_email_alert(result.email, breaches)
                logger.info("Email alert sent successfully")
            except Exception as e:
                logger.error(f"Failed to send email alert: {e}")

    def _build_summary_lines(self, breaches: List[Breach]) -> str:
        summary = DataNormalizer.generate_summary(breaches)
        return (
            f"- Total breaches: {summary['total_breaches']}\n"
            f"- Critical: {summary['critical_breaches']}\n"
            f"- High: {summary['high_breaches']}\n"
            f"- Medium: {summary['medium_breaches']}\n"
            f"- Accounts affected: {summary['total_accounts_affected']:,}"
        )

    def _send_telegram_alert(self, email: str, breaches: List[Breach]) -> None:
        """Send an alert via the Telegram Bot API."""
        url = f"https://api.telegram.org/bot{config.telegram_bot_token}/sendMessage"

        message = "\U0001F6A8 *New Data Breach Alert!*\n\n"
        message += f"\U0001F4E7 *Email:* `{email}`\n"
        message += f"\U0001F4C5 *Date:* {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
        message += f"\U0001F4CA *Summary:*\n{self._build_summary_lines(breaches)}\n\n"
        message += "\U0001F513 *New breaches:*\n"

        for breach in breaches[:5]:
            emoji = SEVERITY_EMOJI.get(breach.severity.value, "\u26AA")
            message += (
                f"\n{emoji} *{breach.title}*\n"
                f"  Domain: {breach.domain}\n"
                f"  Date: {breach.breach_date.strftime('%Y-%m-%d')}\n"
                f"  Accounts: {breach.pwn_count:,}\n"
                f"  Data: {', '.join(breach.data_classes[:3])}\n"
            )

        if len(breaches) > 5:
            message += f"\n... and {len(breaches) - 5} more breaches\n"

        message += "\n\U000026A0 *Recommended actions:*\n"
        message += "- Change passwords immediately\n"
        message += "- Enable two-factor authentication\n"
        message += "- Monitor financial accounts\n"
        message += "- Watch for phishing emails\n"

        payload = {"chat_id": config.telegram_chat_id, "text": message, "parse_mode": "Markdown"}
        response = requests.post(url, json=payload, timeout=10)

        if response.status_code != 200:
            raise Exception(f"Telegram API error: {response.text}")

    def _send_discord_alert(self, email: str, breaches: List[Breach]) -> None:
        """Send an alert via a Discord webhook."""
        summary = DataNormalizer.generate_summary(breaches)

        embed = {
            "title": "\U0001F6A8 New Data Breach Alert!",
            "description": f"New breaches detected for email: `{email}`",
            "color": 15158332,
            "fields": [
                {
                    "name": "\U0001F4CA Summary",
                    "value": (
                        f"**Total breaches:** {summary['total_breaches']}\n"
                        f"**Critical:** {summary['critical_breaches']}\n"
                        f"**High:** {summary['high_breaches']}"
                    ),
                    "inline": False,
                }
            ],
            "timestamp": datetime.now().isoformat(),
            "footer": {"text": "LeakRadar"},
        }

        for breach in breaches[:5]:
            embed["fields"].append(
                {
                    "name": f"\U0001F513 {breach.title}",
                    "value": (
                        f"**Domain:** {breach.domain}\n"
                        f"**Date:** {breach.breach_date.strftime('%Y-%m-%d')}\n"
                        f"**Accounts:** {breach.pwn_count:,}"
                    ),
                    "inline": False,
                }
            )

        payload = {"username": "LeakRadar", "embeds": [embed]}
        response = requests.post(config.discord_webhook_url, json=payload, timeout=10)

        if response.status_code not in [200, 204]:
            raise Exception(f"Discord webhook error: {response.text}")

    def _send_email_alert(self, email: str, breaches: List[Breach]) -> None:
        """Send an alert via SMTP email."""
        summary = DataNormalizer.generate_summary(breaches)

        html = f"""<html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #e74c3c;">\U0001F6A8 New Data Breach Alert!</h1>
                <p>New breaches detected for email: <strong>{email}</strong></p>
                <p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
                <h2 style="color: #3498db;">\U0001F4CA Summary</h2>
                <ul>
                    <li><strong>Total breaches:</strong> {summary['total_breaches']}</li>
                    <li><strong>Critical:</strong> {summary['critical_breaches']}</li>
                    <li><strong>High:</strong> {summary['high_breaches']}</li>
                    <li><strong>Medium:</strong> {summary['medium_breaches']}</li>
                    <li><strong>Accounts affected:</strong> {summary['total_accounts_affected']:,}</li>
                </ul>
                <h2 style="color: #3498db;">\U0001F513 New Breaches</h2>"""

        for breach in breaches[:5]:
            html += f"""
                <div style="border-left: 4px solid #e74c3c; padding-left: 15px; margin: 15px 0;">
                    <h3 style="color: #e74c3c;">{breach.title}</h3>
                    <p><strong>Domain:</strong> {breach.domain}</p>
                    <p><strong>Date:</strong> {breach.breach_date.strftime('%Y-%m-%d')}</p>
                    <p><strong>Accounts affected:</strong> {breach.pwn_count:,}</p>
                    <p><strong>Exposed data:</strong> {', '.join(breach.data_classes)}</p>
                </div>"""

        html += """
                <h2 style="color: #3498db;">\u26A0 Recommended Actions</h2>
                <ul>
                    <li>Change passwords immediately</li>
                    <li>Enable two-factor authentication (2FA)</li>
                    <li>Monitor financial accounts</li>
                    <li>Watch for phishing emails</li>
                    <li>Use a password manager</li>
                </ul>
                <hr style="margin: 30px 0;">
                <p style="color: #7f8c8d; font-size: 12px;">
                    This email was sent automatically by LeakRadar.
                </p>
            </div>
        </body>
        </html>"""

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"\U0001F6A8 Data Breach Alert - {email}"
        msg["From"] = config.smtp_from
        msg["To"] = config.smtp_to
        msg.attach(MIMEText(html, "html"))

        try:
            server = smtplib.SMTP(config.smtp_server, config.smtp_port)
            server.starttls()
            server.login(config.smtp_username, config.smtp_password)
            server.send_message(msg)
            server.quit()
        except Exception as e:
            raise Exception(f"SMTP error: {e}")
