"""
Advanced caching system with multiple cache types and optimizations
"""
import asyncio
import hashlib
import logging
import pickle
import threading
import time
import weakref
from collections import OrderedDict, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple, Union

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Cache entry with metadata"""
    value: Any
    created_at: float
    accessed_at: float
    access_count: int
    ttl: Optional[float] = None

    def is_expired(self) -> bool:
        """Check if entry is expired"""
        if self.ttl is None:
            return False
        return time.time() - self.created_at > self.ttl

    def update_access(self):
        """Update access metadata"""
        self.accessed_at = time.time()
        self.access_count += 1


class LRUCache:
    """Thread-safe LRU cache with TTL support"""

    def __init__(self, max_size: int = 1000, default_ttl: Optional[float] = None):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'expired': 0
        }

    def _make_key(self, key: Any) -> str:
        """Convert key to string"""
        if isinstance(key, str):
            return key
        elif isinstance(key, (int, float, bool)):
            return str(key)
        else:
            # Hash complex objects
            return hashlib.sha256(str(key).encode()).hexdigest()[:16]

    def get(self, key: Any) -> Optional[Any]:
        """Get value from cache"""
        str_key = self._make_key(key)

        with self._lock:
            if str_key not in self._cache:
                self.stats['misses'] += 1
                return None

            entry = self._cache[str_key]

            # Check if expired
            if entry.is_expired():
                del self._cache[str_key]
                self.stats['expired'] += 1
                self.stats['misses'] += 1
                return None

            # Update access and move to end (most recently used)
            entry.update_access()
            self._cache.move_to_end(str_key)
            self.stats['hits'] += 1

            return entry.value

    def set(self, key: Any, value: Any, ttl: Optional[float] = None) -> None:
        """Set value in cache"""
        str_key = self._make_key(key)
        ttl = ttl or self.default_ttl

        with self._lock:
            # Create new entry
            entry = CacheEntry(
                value=value,
                created_at=time.time(),
                accessed_at=time.time(),
                access_count=1,
                ttl=ttl
            )

            # Remove if already exists
            if str_key in self._cache:
                del self._cache[str_key]

            # Add new entry
            self._cache[str_key] = entry

            # Evict if over size limit
            while len(self._cache) > self.max_size:
                # Remove least recently used
                oldest_key, _ = self._cache.popitem(last=False)
                self.stats['evictions'] += 1

    def delete(self, key: Any) -> bool:
        """Delete key from cache"""
        str_key = self._make_key(key)

        with self._lock:
            if str_key in self._cache:
                del self._cache[str_key]
                return True
            return False

    def clear(self) -> None:
        """Clear all cache entries"""
        with self._lock:
            self._cache.clear()

    def cleanup_expired(self) -> int:
        """Remove expired entries and return count"""
        expired_count = 0

        with self._lock:
            expired_keys = [
                key for key, entry in self._cache.items()
                if entry.is_expired()
            ]

            for key in expired_keys:
                del self._cache[key]
                expired_count += 1

            self.stats['expired'] += expired_count

        return expired_count

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            total_requests = self.stats['hits'] + self.stats['misses']
            hit_rate = self.stats['hits'] / total_requests if total_requests > 0 else 0

            return {
                'size': len(self._cache),
                'max_size': self.max_size,
                'hits': self.stats['hits'],
                'misses': self.stats['misses'],
                'hit_rate': hit_rate,
                'evictions': self.stats['evictions'],
                'expired': self.stats['expired']
            }


class AsyncLRUCache:
    """Async version of LRU cache with automatic cleanup"""

    def __init__(self, max_size: int = 1000, default_ttl: Optional[float] = None):
        self._cache = LRUCache(max_size, default_ttl)
        self._cleanup_task: Optional[asyncio.Task] = None
        # Use config for cleanup interval if available, otherwise default to 5 minutes
        try:
            from src.core.config import config
            self._cleanup_interval = config.MEMORY_CLEANUP_INTERVAL
        except ImportError:
            self._cleanup_interval = 300  # 5 minutes default

    async def get(self, key: Any) -> Optional[Any]:
        """Get value from cache"""
        return self._cache.get(key)

    async def set(self, key: Any, value: Any, ttl: Optional[float] = None) -> None:
        """Set value in cache"""
        self._cache.set(key, value, ttl)

    async def delete(self, key: Any) -> bool:
        """Delete key from cache"""
        return self._cache.delete(key)

    async def clear(self) -> None:
        """Clear all cache entries"""
        self._cache.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return self._cache.get_stats()

    async def start_cleanup(self):
        """Start automatic cleanup task"""
        if self._cleanup_task and not self._cleanup_task.done():
            return

        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop_cleanup(self):
        """Stop automatic cleanup task"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

    async def _cleanup_loop(self):
        """Automatic cleanup loop"""
        while True:
            try:
                await asyncio.sleep(self._cleanup_interval)
                expired_count = self._cache.cleanup_expired()
                if expired_count > 0:
                    logger.debug(f"Cleaned up {expired_count} expired cache entries")
            except Exception as e:
                logger.error(f"Error in cache cleanup: {e}")
                await asyncio.sleep(60)


class MultiLevelCache:
    """Multi-level caching system (L1: memory, L2: disk)"""

    def __init__(self,
                 l1_size: int = 1000,
                 l2_size: int = 10000,
                 l1_ttl: float = 300,  # 5 minutes
                 l2_ttl: float = 3600):  # 1 hour
        self.l1_cache = AsyncLRUCache(l1_size, l1_ttl)
        self.l2_cache = AsyncLRUCache(l2_size, l2_ttl)

    async def get(self, key: Any) -> Optional[Any]:
        """Get value from cache (L1 first, then L2)"""
        # Try L1 first
        value = await self.l1_cache.get(key)
        if value is not None:
            return value

        # Try L2
        value = await self.l2_cache.get(key)
        if value is not None:
            # Promote to L1
            await self.l1_cache.set(key, value)
            return value

        return None

    async def set(self, key: Any, value: Any) -> None:
        """Set value in both cache levels"""
        await self.l1_cache.set(key, value)
        await self.l2_cache.set(key, value)

    async def delete(self, key: Any) -> bool:
        """Delete from both cache levels"""
        l1_deleted = await self.l1_cache.delete(key)
        l2_deleted = await self.l2_cache.delete(key)
        return l1_deleted or l2_deleted

    async def clear(self) -> None:
        """Clear both cache levels"""
        await self.l1_cache.clear()
        await self.l2_cache.clear()

    async def start_cleanup(self):
        """Start cleanup for both levels"""
        await self.l1_cache.start_cleanup()
        await self.l2_cache.start_cleanup()

    async def stop_cleanup(self):
        """Stop cleanup for both levels"""
        await self.l1_cache.stop_cleanup()
        await self.l2_cache.stop_cleanup()

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics for both cache levels"""
        return {
            'l1': self.l1_cache.get_stats(),
            'l2': self.l2_cache.get_stats()
        }


# Specialized caches for the bot
class DomainCache:
    """Optimized domain cache with bloom filter pre-check"""

    def __init__(self, max_size: int = 50000):
        # Use config for TTL if available, otherwise default to 1 hour
        try:
            from src.core.config import config
            default_ttl = config.DOMAIN_CACHE_TTL
        except ImportError:
            default_ttl = 3600  # 1 hour default

        self._cache = AsyncLRUCache(max_size, default_ttl=default_ttl)
        self._bloom_filter = set()  # Simple set as bloom filter

    async def add_domain(self, domain: str) -> None:
        """Add domain to cache"""
        domain = domain.lower().strip()
        self._bloom_filter.add(domain)
        await self._cache.set(domain, True)

    async def add_domains(self, domains: list) -> None:
        """Add multiple domains efficiently"""
        for domain in domains:
            domain = domain.lower().strip()
            self._bloom_filter.add(domain)
            await self._cache.set(domain, True)

    async def contains(self, domain: str) -> bool:
        """Check if domain exists in cache, including subdomain matching"""
        domain = domain.lower().strip()

        # First check exact match with bloom filter
        if domain in self._bloom_filter:
            result = await self._cache.get(domain)
            if result is True:
                return True

        # Check parent domains for subdomain matching
        # For example: if checking "evil.example.com" and "example.com" is in the blocklist
        parts = domain.split('.')
        for i in range(1, len(parts)):
            parent_domain = '.'.join(parts[i:])
            if parent_domain in self._bloom_filter:
                result = await self._cache.get(parent_domain)
                if result is True:
                    # Cache the subdomain for faster future lookups
                    await self.add_domain(domain)
                    return True

        return False

    def __contains__(self, domain: str) -> bool:
        """Sync version for compatibility - checks exact match and parent domains"""
        domain = domain.lower().strip()

        # Check exact match first
        if domain in self._bloom_filter:
            return True

        # Check parent domains for subdomain matching
        parts = domain.split('.')
        for i in range(1, len(parts)):
            parent_domain = '.'.join(parts[i:])
            if parent_domain in self._bloom_filter:
                return True

        return False

    def __len__(self) -> int:
        """Get cache size"""
        return len(self._bloom_filter)

    async def clear(self) -> None:
        """Clear cache"""
        self._bloom_filter.clear()
        await self._cache.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        stats = self._cache.get_stats()
        stats['bloom_size'] = len(self._bloom_filter)
        return stats


# Import config for cache sizes
from src.core.config import config

# Cache instances for the bot with configurable sizes
result_cache = MultiLevelCache(
    l1_size=config.RESULT_CACHE_L1_SIZE,
    l2_size=config.RESULT_CACHE_L2_SIZE,
    l1_ttl=config.RESULT_CACHE_L1_TTL,
    l2_ttl=config.RESULT_CACHE_L2_TTL
)
domain_cache_phishing = DomainCache(max_size=config.DOMAIN_CACHE_SIZE)
domain_cache_malware = DomainCache(max_size=config.DOMAIN_CACHE_SIZE)
domain_cache_adguard = DomainCache(max_size=config.DOMAIN_CACHE_SIZE)
domain_cache_piracy = DomainCache(max_size=config.DOMAIN_CACHE_SIZE)
