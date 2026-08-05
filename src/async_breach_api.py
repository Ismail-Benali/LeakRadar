"""Async API client for parallel breach checks."""
import asyncio
from typing import List

import aiohttp
from loguru import logger

from src.config import config


class AsyncBreachAPI:
    """Asynchronous variant of the breach API client."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://haveibeenpwned.com/api/v3"

    async def check_multiple_emails(self, emails: List[str]) -> dict:
        """Check several emails in parallel."""
        async with aiohttp.ClientSession() as session:
            tasks = [self._check_email_async(session, email) for email in emails]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            return {
                email: result
                for email, result in zip(emails, results)
                if not isinstance(result, Exception)
            }

    async def _check_email_async(self, session: aiohttp.ClientSession, email: str):
        """Check a single email asynchronously."""
        url = f"{self.base_url}/breachedaccount/{email}"
        headers = {"hibp-api-key": self.api_key}
        params = {"truncateResponse": "false"}

        try:
            async with session.get(
                url, headers=headers, params=params, timeout=config.request_timeout
            ) as response:
                if response.status == 200:
                    return await response.json()
                if response.status == 404:
                    return []
                logger.error(f"Error checking {email}: {response.status}")
                return None
        except Exception as e:
            logger.error(f"Async error checking {email}: {e}")
            return None
