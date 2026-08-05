"""Application configuration loaded from environment variables."""
import os
from typing import List

from dotenv import load_dotenv
from pydantic import BaseModel

load_dotenv()


class Config(BaseModel):
    """Configuration model with basic validation."""

    # Targets
    target_emails: List[str]

    # HIBP
    hibp_api_key: str
    hibp_api_url: str = "https://haveibeenpwned.com/api/v3"

    # Telegram
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None

    # Discord
    discord_webhook_url: str | None = None

    # SMTP
    smtp_server: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    smtp_to: str | None = None

    # Database
    database_url: str = "sqlite:///data/leaks.db"

    # Logging
    log_level: str = "INFO"
    log_file: str = "data/logs/leakradar.log"

    # Scan settings
    scan_interval_hours: int = 1
    max_retries: int = 3
    request_timeout: int = 30


def _as_int(value: str | None, default: int) -> int:
    try:
        return int(value) if value else default
    except ValueError:
        return default


def load_config() -> Config:
    """Load the configuration from environment variables."""
    return Config(
        target_emails=[
            email.strip()
            for email in os.getenv("TARGET_EMAILS", "").split(",")
            if email.strip()
        ],
        hibp_api_key=os.getenv("HIBP_API_KEY", ""),
        hibp_api_url=os.getenv(
            "HIBP_API_URL", "https://haveibeenpwned.com/api/v3"
        ),
        telegram_bot_token=os.getenv("TELEGRAM_BOT_TOKEN"),
        telegram_chat_id=os.getenv("TELEGRAM_CHAT_ID"),
        discord_webhook_url=os.getenv("DISCORD_WEBHOOK_URL"),
        smtp_server=os.getenv("SMTP_SERVER"),
        smtp_port=_as_int(os.getenv("SMTP_PORT"), 587),
        smtp_username=os.getenv("SMTP_USERNAME"),
        smtp_password=os.getenv("SMTP_PASSWORD"),
        smtp_from=os.getenv("SMTP_FROM"),
        smtp_to=os.getenv("SMTP_TO"),
        database_url=os.getenv("DATABASE_URL", "sqlite:///data/leaks.db"),
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        log_file=os.getenv("LOG_FILE", "data/logs/leakradar.log"),
        scan_interval_hours=_as_int(os.getenv("SCAN_INTERVAL_HOURS"), 1),
        max_retries=_as_int(os.getenv("MAX_RETRIES"), 3),
        request_timeout=_as_int(os.getenv("REQUEST_TIMEOUT"), 30),
    )


config = load_config()
