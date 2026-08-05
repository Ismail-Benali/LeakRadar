"""Data normalization and enrichment utilities."""
from datetime import datetime
from typing import List

from loguru import logger

from src.models import Breach


class DataNormalizer:
    """Utilities to normalize and enrich breach data."""

    @staticmethod
    def normalize_email(email: str) -> str:
        """Normalize an email address."""
        return email.lower().strip()

    @staticmethod
    def extract_domain(email: str) -> str:
        """Extract the domain from an email address."""
        try:
            return email.split("@")[1].lower()
        except (IndexError, AttributeError):
            return ""

    @staticmethod
    def classify_data_types(data_classes: List[str]) -> dict:
        """Classify exposed data types into categories."""
        categories = {
            "credentials": [],
            "personal_info": [],
            "financial": [],
            "other": [],
        }

        credential_keywords = ["password", "username", "email"]
        personal_keywords = ["name", "phone", "address", "date of birth", "ssn"]
        financial_keywords = ["credit card", "bank account", "ip address"]

        for data_type in data_classes:
            data_lower = data_type.lower()

            if any(keyword in data_lower for keyword in credential_keywords):
                categories["credentials"].append(data_type)
            elif any(keyword in data_lower for keyword in personal_keywords):
                categories["personal_info"].append(data_type)
            elif any(keyword in data_lower for keyword in financial_keywords):
                categories["financial"].append(data_type)
            else:
                categories["other"].append(data_type)

        return categories

    @staticmethod
    def calculate_risk_score(breach: Breach) -> int:
        """Compute a 0-100 risk score for a breach."""
        score = 0
        data_lower = [d.lower() for d in breach.data_classes]

        def contains_any(keywords) -> bool:
            return any(kw in text for text in data_lower for kw in keywords)

        if contains_any(["password"]):
            score += 40
        if contains_any(["credit card"]):
            score += 30
        if contains_any(["ssn", "social security"]):
            score += 30
        if contains_any(["phone"]):
            score += 10
        if contains_any(["address"]):
            score += 10

        if breach.pwn_count > 1_000_000:
            score += 20
        elif breach.pwn_count > 100_000:
            score += 10
        elif breach.pwn_count > 10_000:
            score += 5

        if breach.is_verified:
            score += 10

        days_old = (datetime.now() - breach.breach_date).days
        if days_old > 365 * 2:
            score -= 20
        elif days_old > 365:
            score -= 10

        return max(0, min(100, score))

    @staticmethod
    def generate_summary(breaches: List[Breach]) -> dict:
        """Generate a summary for a list of breaches."""
        if not breaches:
            return {
                "total_breaches": 0,
                "critical_breaches": 0,
                "high_breaches": 0,
                "medium_breaches": 0,
                "low_breaches": 0,
                "total_accounts_affected": 0,
                "data_types_found": [],
            }

        summary = {
            "total_breaches": len(breaches),
            "critical_breaches": sum(1 for b in breaches if b.severity.value == "critical"),
            "high_breaches": sum(1 for b in breaches if b.severity.value == "high"),
            "medium_breaches": sum(1 for b in breaches if b.severity.value == "medium"),
            "low_breaches": sum(1 for b in breaches if b.severity.value == "low"),
            "total_accounts_affected": sum(b.pwn_count for b in breaches),
            "data_types_found": [],
        }

        data_types: set = set()
        for breach in breaches:
            data_types.update(breach.data_classes)
        summary["data_types_found"] = sorted(data_types)

        logger.debug(f"Generated summary: {summary}")
        return summary
