"""API client layer for breach intelligence sources."""
import time
from datetime import datetime
from typing import List, Optional

import requests
from loguru import logger

from src.config import config
from src.models import Breach


class BreachAPIError(Exception):
    """Custom exception for API errors."""

    pass


class HaveIBeenPwnedAPI:
    """Client for the Have I Been Pwned (HIBP) v3 API."""

    def __init__(self, api_key: str, base_url: str = "https://haveibeenpwned.com/api/v3"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "hibp-api-key": api_key,
                "user-agent": "LeakRadar/1.0",
                "Content-Type": "application/json",
            }
        )

    def _make_request(self, endpoint: str, params: Optional[dict] = None) -> dict | list:
        """Perform an HTTP request with retries and error handling."""
        url = f"{self.base_url}/{endpoint}"

        for attempt in range(config.max_retries):
            try:
                logger.debug(f"Request attempt {attempt + 1} to {url}")

                response = self.session.get(
                    url, params=params, timeout=config.request_timeout
                )

                if response.status_code == 200:
                    return response.json()
                if response.status_code == 404:
                    return []
                if response.status_code == 401:
                    raise BreachAPIError("Invalid API key")
                if response.status_code == 403:
                    raise BreachAPIError("Access forbidden - check your API key")
                if response.status_code == 429:
                    wait_time = int(response.headers.get("Retry-After", 60))
                    logger.warning(f"Rate limit reached, waiting {wait_time}s")
                    time.sleep(wait_time)
                    continue
                if response.status_code == 503:
                    logger.warning(f"Service unavailable, attempt {attempt + 1}")
                    time.sleep(2**attempt)
                    continue
                raise BreachAPIError(f"HTTP {response.status_code}: {response.text}")

            except requests.exceptions.Timeout:
                logger.error(f"Request timeout on attempt {attempt + 1}")
                if attempt == config.max_retries - 1:
                    raise BreachAPIError("Request timeout after all retries")
                time.sleep(2**attempt)
            except requests.exceptions.ConnectionError:
                logger.error(f"Connection error on attempt {attempt + 1}")
                if attempt == config.max_retries - 1:
                    raise BreachAPIError("Connection failed after all retries")
                time.sleep(2**attempt)
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                if attempt == config.max_retries - 1:
                    raise BreachAPIError(f"Unexpected error: {e}")
                time.sleep(2**attempt)

        raise BreachAPIError("Failed after all retries")

    @staticmethod
    def _to_breach(item: dict) -> Breach:
        def _parse(value: str | None) -> datetime:
            if not value:
                return datetime(2000, 1, 1)
            return datetime.fromisoformat(value.replace("Z", "+00:00"))

        return Breach(
            name=item.get("Name", ""),
            title=item.get("Title", ""),
            domain=item.get("Domain", ""),
            breach_date=_parse(item.get("BreachDate")),
            added_date=_parse(item.get("AddedDate")),
            modified_date=_parse(item.get("ModifiedDate")) if item.get("ModifiedDate") else None,
            pwn_count=item.get("PwnCount", 0),
            description=item.get("Description", ""),
            logo_path=item.get("LogoPath"),
            data_classes=item.get("DataClasses", []),
            is_verified=item.get("IsVerified", False),
            is_fabricated=item.get("IsFabricated", False),
            is_sensitive=item.get("IsSensitive", False),
            is_retired=item.get("IsRetired", False),
            is_spam_list=item.get("IsSpamList", False),
        )

    def get_breached_account(self, email: str) -> List[Breach]:
        """Check whether an email address has been involved in a breach."""
        logger.info(f"Checking breaches for email: {email}")

        endpoint = f"breachedaccount/{email}"
        params = {"truncateResponse": "false", "includeUnverified": "false"}
        response_data = self._make_request(endpoint, params)

        if not response_data:
            logger.info(f"No breaches found for {email}")
            return []

        breaches = [self._to_breach(item) for item in response_data]
        logger.info(f"Found {len(breaches)} breaches for {email}")
        return breaches

    def get_all_breaches(self) -> List[Breach]:
        """Fetch a list of all known breaches."""
        logger.info("Fetching all breaches")

        response_data = self._make_request("breaches")
        breaches = [self._to_breach(item) for item in response_data]

        logger.info(f"Fetched {len(breaches)} breaches")
        return breaches

    def get_pastes_for_email(self, email: str) -> List[dict]:
        """Search for pastes that contain the given email address."""
        logger.info(f"Checking pastes for email: {email}")

        response_data = self._make_request(f"pasteaccount/{email}")

        if not response_data:
            logger.info(f"No pastes found for {email}")
            return []

        logger.info(f"Found {len(response_data)} pastes for {email}")
        return response_data


class DeHashedAPI:
    """Client for the DeHashed API (optional)."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.dehashed.com"
        self.session = requests.Session()
        self.session.headers.update(
            {"Accept": "application/json", "Authorization": f"Basic {api_key}"}
        )

    def search(self, query: str) -> dict:
        """Search the DeHashed database."""
        logger.info(f"Searching DeHashed for: {query}")

        params = {"query": query, "page": 1, "size": 100}

        try:
            response = self.session.get(
                f"{self.base_url}/search",
                params=params,
                timeout=config.request_timeout,
            )

            if response.status_code == 200:
                return response.json()
            raise BreachAPIError(f"HTTP {response.status_code}: {response.text}")

        except Exception as e:
            logger.error(f"DeHashed API error: {e}")
            raise
