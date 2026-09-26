"""Security utilities: ownership validation and audit logging."""
from functools import wraps
from typing import List

from loguru import logger


def validate_email_ownership(email: str, allowed_domains: List[str]) -> bool:
    """Validate that an email belongs to an allowed domain (case-insensitive)."""
    if not email or "@" not in email:
        logger.warning(f"Invalid email format: {email}")
        return False

    domain = email.strip().split("@")[-1].lower()
    normalized_allowed = [d.lower() for d in allowed_domains]

    if domain not in normalized_allowed:
        logger.warning(f"Unauthorized domain: {domain}")
        return False

    return True


def audit_log(action: str, email: str, user: str = "system") -> None:
    """Log an auditable action."""
    logger.info(f"AUDIT: {action} | Email: {email} | User: {user}")


def audit(action: str):
    """Decorator that records an audit entry for the wrapped function."""

    def decorator(func):
        @wraps(func)
        def wrapper(email: str, *args, **kwargs):
            audit_log(action, email)
            return func(email, *args, **kwargs)

        return wrapper

    return decorator


class SecurityManager:
    """Manage authorization for scan operations."""

    def __init__(self, allowed_domains: List[str]):
        self.allowed_domains = allowed_domains

    def authorize_scan(self, email: str) -> bool:
        """Check whether an email is authorized to be scanned."""
        if not validate_email_ownership(email, self.allowed_domains):
            audit_log("UNAUTHORIZED_SCAN_ATTEMPT", email)
            return False

        audit_log("AUTHORIZED_SCAN", email)
        return True
