"""Entry point for the LeakRadar application."""
import sys
from pathlib import Path

from loguru import logger

from src.config import config
from src.scheduler import LeakRadar


def setup_logging() -> None:
    """Configure console and file logging."""
    logger.remove()

    logger.add(
        sys.stderr,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        ),
        level=config.log_level,
    )

    log_path = Path(config.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger.add(
        config.log_file,
        rotation="10 MB",
        retention="30 days",
        compression="zip",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        level=config.log_level,
    )


def main() -> None:
    """Application entry point."""
    setup_logging()

    logger.info("=" * 60)
    logger.info("LeakRadar Starting")
    logger.info("=" * 60)
    logger.info(f"Monitoring {len(config.target_emails)} email(s)")
    logger.info(f"Scan interval: {config.scan_interval_hours} hour(s)")
    logger.info(f"Database: {config.database_url}")
    logger.info("=" * 60)

    monitor = LeakRadar()
    monitor.run_scheduled()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Shutdown requested by user")
    except Exception as e:
        logger.critical(f"Fatal error: {e}")
        sys.exit(1)
