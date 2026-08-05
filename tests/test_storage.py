"""Tests for the SQLite storage layer."""
import tempfile
from datetime import datetime
from pathlib import Path

from src.models import Breach
from src.storage import BreachStorage


def _make_breach(name: str, domain: str = "example.com", pwn_count: int = 100) -> Breach:
    now = datetime.now()
    return Breach(
        name=name,
        title=name.title(),
        domain=domain,
        breach_date=now,
        added_date=now,
        pwn_count=pwn_count,
        description="Test breach",
        data_classes=["Email addresses"],
        is_verified=True,
    )


def _storage(tmp_dir: str) -> BreachStorage:
    return BreachStorage(db_url=f"sqlite:///{tmp_dir}/test.db")


def test_save_and_retrieve_breaches():
    with tempfile.TemporaryDirectory() as tmp_dir:
        storage = _storage(tmp_dir)
        email = "test@example.com"

        storage.save_breaches(email, [_make_breach("BreachA"), _make_breach("BreachB")])
        breaches = storage.get_all_breaches_for_email(email)

        assert len(breaches) == 2
        assert {b.name for b in breaches} == {"BreachA", "BreachB"}


def test_save_breaches_is_idempotent():
    with tempfile.TemporaryDirectory() as tmp_dir:
        storage = _storage(tmp_dir)
        email = "test@example.com"

        first = storage.save_breaches(email, [_make_breach("BreachA")])
        second = storage.save_breaches(email, [_make_breach("BreachA")])

        assert len(first) == 1
        assert len(second) == 0
        assert len(storage.get_all_breaches_for_email(email)) == 1


def test_get_recent_breaches():
    with tempfile.TemporaryDirectory() as tmp_dir:
        storage = _storage(tmp_dir)
        email = "test@example.com"

        storage.save_breaches(email, [_make_breach("BreachA")])
        recent = storage.get_recent_breaches(days=7)

        assert len(recent) == 1
        assert recent[0][2] == "BreachA"


def test_mark_alert_sent():
    with tempfile.TemporaryDirectory() as tmp_dir:
        storage = _storage(tmp_dir)
        storage.mark_alert_sent("test@example.com", "BreachA", "telegram")

        db_file = Path(tmp_dir) / "test.db"
        assert db_file.exists()
