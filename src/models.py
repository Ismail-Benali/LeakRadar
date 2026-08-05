"""Pydantic data models for LeakRadar."""
from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class BreachSeverity(str, Enum):
    """Severity classification for a breach."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DataType(str, Enum):
    """Types of exposed data."""

    EMAIL = "email"
    PASSWORD = "password"
    USERNAME = "username"
    PHONE = "phone"
    ADDRESS = "address"
    IP_ADDRESS = "ip_address"
    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    OTHER = "other"


class Breach(BaseModel):
    """A single data breach record."""

    name: str = Field(..., description="Breach identifier")
    title: str = Field(..., description="Breach display title")
    domain: str = Field(..., description="Affected domain")
    breach_date: datetime = Field(..., description="When the breach occurred")
    added_date: datetime = Field(..., description="When the breach was indexed")
    modified_date: Optional[datetime] = Field(None, description="Last modification date")
    pwn_count: int = Field(..., description="Number of affected accounts")
    description: str = Field(..., description="Breach description")
    logo_path: Optional[str] = Field(None, description="Logo URL")
    data_classes: List[str] = Field(..., description="Exposed data types")
    is_verified: bool = Field(..., description="Is the breach verified?")
    is_fabricated: bool = Field(False, description="Is the breach fabricated?")
    is_sensitive: bool = Field(False, description="Is the breach sensitive?")
    is_retired: bool = Field(False, description="Is the breach retired?")
    is_spam_list: bool = Field(False, description="Is it a spam list?")

    @property
    def severity(self) -> BreachSeverity:
        """Compute severity based on exposed data types."""
        sensitive_types = {"password", "credit card", "ssn", "phone", "address"}
        data_lower = [d.lower() for d in self.data_classes]

        def contains_any(keywords) -> bool:
            return any(kw in text for text in data_lower for kw in keywords)

        if contains_any(["password", "credit card", "ssn"]):
            return BreachSeverity.CRITICAL
        if contains_any(sensitive_types):
            return BreachSeverity.HIGH
        if len(data_lower) > 3:
            return BreachSeverity.MEDIUM
        return BreachSeverity.LOW

    def to_dict(self) -> dict:
        """Convert the breach to a dictionary."""
        return self.model_dump()


class BreachCheckResult(BaseModel):
    """The result of checking a single email address."""

    email: str
    breaches: List[Breach]
    check_date: datetime = Field(default_factory=datetime.now)
    is_new: bool = Field(..., description="Are there new breaches?")

    @property
    def breach_count(self) -> int:
        return len(self.breaches)
