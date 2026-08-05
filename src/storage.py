"""SQLite storage layer for breach data."""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator, List

from loguru import logger

from src.config import config
from src.models import Breach, BreachCheckResult
from src.normalizer import DataNormalizer


@contextmanager
def _db_connection(db_path: str) -> Iterator[sqlite3.Connection]:
    """Open a SQLite connection and guarantee it is closed afterwards."""
    conn = sqlite3.connect(db_path)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


class BreachStorage:
    """Manage persistence of breach data in SQLite."""

    def __init__(self, db_url: str = "sqlite:///data/leaks.db"):
        self.db_path = db_url.replace("sqlite:///", "")
        self._ensure_directory()
        self._init_database()

    def _ensure_directory(self) -> None:
        db_file = Path(self.db_path)
        db_file.parent.mkdir(parents=True, exist_ok=True)

        log_dir = Path(config.log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)

    def _init_database(self) -> None:
        with _db_connection(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS breaches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL,
                    breach_name TEXT NOT NULL,
                    breach_title TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    breach_date TEXT NOT NULL,
                    added_date TEXT NOT NULL,
                    pwn_count INTEGER NOT NULL,
                    description TEXT,
                    data_classes TEXT,
                    is_verified BOOLEAN,
                    severity TEXT,
                    risk_score INTEGER,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    UNIQUE(email, breach_name)
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS check_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL,
                    check_date TEXT NOT NULL,
                    breach_count INTEGER NOT NULL,
                    new_breaches INTEGER NOT NULL,
                    summary TEXT
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL,
                    breach_name TEXT NOT NULL,
                    alert_date TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    sent BOOLEAN DEFAULT 0,
                    sent_date TEXT
                )
                """
            )

            conn.commit()
            logger.info(f"Database initialized at {self.db_path}")

    def save_breaches(self, email: str, breaches: List[Breach]) -> List[Breach]:
        """Persist breaches and return only the newly detected ones."""
        new_breaches: List[Breach] = []

        with _db_connection(self.db_path) as conn:
            cursor = conn.cursor()

            for breach in breaches:
                try:
                    cursor.execute(
                        """
                        SELECT id FROM breaches
                        WHERE email = ? AND breach_name = ?
                        """,
                        (email, breach.name),
                    )

                    if cursor.fetchone():
                        cursor.execute(
                            """
                            UPDATE breaches
                            SET last_seen = ?
                            WHERE email = ? AND breach_name = ?
                            """,
                            (datetime.now().isoformat(), email, breach.name),
                        )
                        continue

                    cursor.execute(
                        """
                        INSERT INTO breaches
                        (email, breach_name, breach_title, domain, breach_date,
                         added_date, pwn_count, description, data_classes,
                         is_verified, severity, risk_score, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            email,
                            breach.name,
                            breach.title,
                            breach.domain,
                            breach.breach_date.isoformat(),
                            breach.added_date.isoformat(),
                            breach.pwn_count,
                            breach.description,
                            json.dumps(breach.data_classes),
                            breach.is_verified,
                            breach.severity.value,
                            DataNormalizer.calculate_risk_score(breach),
                            datetime.now().isoformat(),
                            datetime.now().isoformat(),
                        ),
                    )

                    new_breaches.append(breach)
                    logger.info(f"New breach saved: {breach.name} for {email}")

                except Exception as e:
                    logger.error(f"Error saving breach {breach.name}: {e}")

            conn.commit()

        return new_breaches

    def save_check_result(self, result: BreachCheckResult) -> None:
        """Persist a check result."""
        with _db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            summary = DataNormalizer.generate_summary(result.breaches)

            cursor.execute(
                """
                INSERT INTO check_results
                (email, check_date, breach_count, new_breaches, summary)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    result.email,
                    result.check_date.isoformat(),
                    result.breach_count,
                    len([b for b in result.breaches if result.is_new]),
                    json.dumps(summary),
                ),
            )

            conn.commit()

    def get_all_breaches_for_email(self, email: str) -> List[Breach]:
        """Retrieve all breaches recorded for an email address."""
        with _db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM breaches WHERE email = ? ORDER BY first_seen DESC",
                (email,),
            )
            rows = cursor.fetchall()

        breaches: List[Breach] = []
        for row in rows:
            breaches.append(
                Breach(
                    name=row[2],
                    title=row[3],
                    domain=row[4],
                    breach_date=datetime.fromisoformat(row[5]),
                    added_date=datetime.fromisoformat(row[6]),
                    pwn_count=row[7],
                    description=row[8] or "",
                    data_classes=json.loads(row[9]),
                    is_verified=bool(row[10]),
                )
            )

        return breaches

    def get_recent_breaches(self, days: int = 7) -> List[tuple]:
        """Retrieve breaches first seen within the last `days` days."""
        cutoff_date = datetime.now() - timedelta(days=days)

        with _db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM breaches
                WHERE first_seen >= ?
                ORDER BY first_seen DESC
                """,
                (cutoff_date.isoformat(),),
            )
            return cursor.fetchall()

    def mark_alert_sent(self, email: str, breach_name: str, alert_type: str) -> None:
        """Record that an alert has been sent."""
        with _db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO alerts
                (email, breach_name, alert_date, alert_type, sent, sent_date)
                VALUES (?, ?, ?, ?, 1, ?)
                """,
                (
                    email,
                    breach_name,
                    datetime.now().isoformat(),
                    alert_type,
                    datetime.now().isoformat(),
                ),
            )
            conn.commit()
