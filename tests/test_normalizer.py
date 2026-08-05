"""Tests for the data normalizer."""
from datetime import datetime

from src.models import Breach
from src.normalizer import DataNormalizer


def test_normalize_email():
    assert DataNormalizer.normalize_email("  TEST@Example.COM  ") == "test@example.com"
    assert DataNormalizer.normalize_email("user@domain.com") == "user@domain.com"


def test_extract_domain():
    assert DataNormalizer.extract_domain("user@example.com") == "example.com"
    assert DataNormalizer.extract_domain("invalid-email") == ""


def test_calculate_risk_score():
    breach = Breach(
        name="Test",
        title="Test Breach",
        domain="example.com",
        breach_date=datetime.now(),
        added_date=datetime.now(),
        pwn_count=100000,
        description="Test",
        data_classes=["Passwords", "Email addresses"],
        is_verified=True,
    )

    score = DataNormalizer.calculate_risk_score(breach)

    assert 0 <= score <= 100
    assert score > 50


def test_classify_data_types():
    data_classes = [
        "Email addresses",
        "Passwords",
        "Phone numbers",
        "Credit cards",
        "IP addresses",
    ]

    categories = DataNormalizer.classify_data_types(data_classes)

    assert "Email addresses" in categories["credentials"]
    assert "Passwords" in categories["credentials"]
    assert "Phone numbers" in categories["personal_info"]
    assert "Credit cards" in categories["financial"]


def test_generate_summary_empty():
    summary = DataNormalizer.generate_summary([])

    assert summary["total_breaches"] == 0
    assert summary["critical_breaches"] == 0


def test_severity_classification():
    breach = Breach(
        name="Critical",
        title="Critical Breach",
        domain="example.com",
        breach_date=datetime.now(),
        added_date=datetime.now(),
        pwn_count=5000,
        description="Test",
        data_classes=["Email addresses", "Passwords"],
        is_verified=True,
    )

    assert breach.severity.value == "critical"
