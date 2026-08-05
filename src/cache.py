"""Optional Redis-backed caching layer."""
import json
from typing import List, Optional

from loguru import logger

from src.models import Breach


class BreachCache:
    """Redis-backed cache for breach lookups."""

    def __init__(self, host: str = "localhost", port: int = 6379):
        import redis

        self.redis_client = redis.Redis(
            host=host, port=port, db=0, decode_responses=True
        )
        self.ttl = 3600

    def get_breaches(self, email: str) -> Optional[List[dict]]:
        """Retrieve cached breaches for an email, if any."""
        cached = self.redis_client.get(f"breaches:{email}")
        if cached:
            return json.loads(cached)
        return None

    def set_breaches(self, email: str, breaches: List[Breach]) -> None:
        """Cache breaches for an email with a TTL."""
        self.redis_client.setex(
            f"breaches:{email}",
            self.ttl,
            json.dumps([b.model_dump() for b in breaches]),
        )

    def invalidate(self, email: str) -> None:
        """Remove cached breaches for an email."""
        self.redis_client.delete(f"breaches:{email}")


class NullCache:
    """No-op cache used when Redis is unavailable."""

    def get_breaches(self, email: str) -> Optional[List[dict]]:
        return None

    def set_breaches(self, email: str, breaches: List[Breach]) -> None:
        pass

    def invalidate(self, email: str) -> None:
        pass


def get_cache() -> BreachCache | NullCache:
    """Return a cache instance, falling back to NullCache when Redis is off."""
    try:
        return BreachCache()
    except Exception as e:
        logger.warning(f"Redis unavailable, using NullCache: {e}")
        return NullCache()
