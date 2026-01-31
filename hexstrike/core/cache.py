"""
O(1) LRU Cache Implementation

High-performance LRU (Least Recently Used) cache with:
- O(1) get, put, and eviction operations
- TTL (Time-To-Live) support
- Thread-safe operations
- Statistics tracking
"""

import time
import threading
import logging
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional, Any, Dict, Callable, TypeVar, Generic, Tuple

logger = logging.getLogger(__name__)

K = TypeVar('K')
V = TypeVar('V')


@dataclass
class CacheEntry(Generic[V]):
    """Represents a single cache entry with metadata."""
    value: V
    created_at: float
    accessed_at: float
    ttl: Optional[float] = None
    hit_count: int = 0

    def is_expired(self) -> bool:
        """Check if the entry has expired."""
        if self.ttl is None:
            return False
        return time.time() > self.created_at + self.ttl


@dataclass
class CacheStats:
    """Cache statistics."""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    expirations: int = 0
    total_puts: int = 0

    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary."""
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "expirations": self.expirations,
            "total_puts": self.total_puts,
            "hit_rate": round(self.hit_rate, 4),
        }


class LRUCache(Generic[K, V]):
    """
    O(1) LRU Cache with TTL support.

    Uses OrderedDict for O(1) operations:
    - get: O(1)
    - put: O(1)
    - eviction: O(1) via popitem(last=False)

    Thread-safe with optional locking.
    """

    def __init__(self,
                 max_size: int = 1000,
                 default_ttl: Optional[float] = None,
                 thread_safe: bool = True,
                 on_evict: Optional[Callable[[K, V], None]] = None):
        """
        Initialize LRU cache.

        Args:
            max_size: Maximum number of entries
            default_ttl: Default TTL in seconds (None = no expiration)
            thread_safe: Enable thread-safe operations
            on_evict: Callback function when entry is evicted
        """
        self._cache: OrderedDict[K, CacheEntry[V]] = OrderedDict()
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._on_evict = on_evict
        self._stats = CacheStats()
        self._lock = threading.RLock() if thread_safe else None

    def _acquire_lock(self) -> None:
        """Acquire lock if thread safety is enabled."""
        if self._lock:
            self._lock.acquire()

    def _release_lock(self) -> None:
        """Release lock if thread safety is enabled."""
        if self._lock:
            self._lock.release()

    def get(self, key: K, default: Optional[V] = None) -> Optional[V]:
        """
        Get value from cache.

        O(1) operation. Moves accessed item to end (most recent).

        Args:
            key: Cache key
            default: Default value if key not found

        Returns:
            Cached value or default
        """
        self._acquire_lock()
        try:
            if key not in self._cache:
                self._stats.misses += 1
                return default

            entry = self._cache[key]

            # Check expiration
            if entry.is_expired():
                self._remove_entry(key)
                self._stats.expirations += 1
                self._stats.misses += 1
                return default

            # Move to end (most recently used) - O(1)
            self._cache.move_to_end(key)

            # Update access time and hit count
            entry.accessed_at = time.time()
            entry.hit_count += 1
            self._stats.hits += 1

            return entry.value

        finally:
            self._release_lock()

    def put(self,
            key: K,
            value: V,
            ttl: Optional[float] = None) -> None:
        """
        Put value into cache.

        O(1) operation. Evicts LRU item if at capacity.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Optional TTL override for this entry
        """
        self._acquire_lock()
        try:
            now = time.time()

            # If key exists, update it
            if key in self._cache:
                self._cache[key].value = value
                self._cache[key].accessed_at = now
                if ttl is not None:
                    self._cache[key].ttl = ttl
                    self._cache[key].created_at = now
                self._cache.move_to_end(key)
                return

            # Check capacity and evict if needed
            while len(self._cache) >= self._max_size:
                self._evict_lru()

            # Add new entry
            entry = CacheEntry(
                value=value,
                created_at=now,
                accessed_at=now,
                ttl=ttl if ttl is not None else self._default_ttl
            )
            self._cache[key] = entry
            self._stats.total_puts += 1

        finally:
            self._release_lock()

    def _evict_lru(self) -> None:
        """
        Evict least recently used entry.

        O(1) operation using OrderedDict.popitem(last=False).
        """
        if not self._cache:
            return

        # popitem(last=False) removes the first (oldest) item - O(1)
        key, entry = self._cache.popitem(last=False)
        self._stats.evictions += 1

        # Call eviction callback if set
        if self._on_evict:
            try:
                self._on_evict(key, entry.value)
            except Exception as e:
                logger.warning(f"Eviction callback failed: {e}")

    def _remove_entry(self, key: K) -> None:
        """Remove an entry from cache."""
        if key in self._cache:
            entry = self._cache.pop(key)
            if self._on_evict:
                try:
                    self._on_evict(key, entry.value)
                except Exception as e:
                    logger.warning(f"Eviction callback failed: {e}")

    def delete(self, key: K) -> bool:
        """
        Delete entry from cache.

        Args:
            key: Cache key

        Returns:
            True if key was present and deleted
        """
        self._acquire_lock()
        try:
            if key in self._cache:
                self._remove_entry(key)
                return True
            return False
        finally:
            self._release_lock()

    def clear(self) -> None:
        """Clear all entries from cache."""
        self._acquire_lock()
        try:
            self._cache.clear()
        finally:
            self._release_lock()

    def contains(self, key: K) -> bool:
        """
        Check if key exists in cache (without updating access time).

        Args:
            key: Cache key

        Returns:
            True if key exists and is not expired
        """
        self._acquire_lock()
        try:
            if key not in self._cache:
                return False

            entry = self._cache[key]
            if entry.is_expired():
                self._remove_entry(key)
                self._stats.expirations += 1
                return False

            return True
        finally:
            self._release_lock()

    def __contains__(self, key: K) -> bool:
        """Support 'in' operator."""
        return self.contains(key)

    def __len__(self) -> int:
        """Return number of entries in cache."""
        return len(self._cache)

    def __getitem__(self, key: K) -> V:
        """Support bracket access."""
        value = self.get(key)
        if value is None and key not in self._cache:
            raise KeyError(key)
        return value

    def __setitem__(self, key: K, value: V) -> None:
        """Support bracket assignment."""
        self.put(key, value)

    def __delitem__(self, key: K) -> None:
        """Support del operator."""
        if not self.delete(key):
            raise KeyError(key)

    def get_or_compute(self,
                      key: K,
                      compute_func: Callable[[], V],
                      ttl: Optional[float] = None) -> V:
        """
        Get value from cache or compute and store it.

        Args:
            key: Cache key
            compute_func: Function to compute value if not cached
            ttl: Optional TTL for new entry

        Returns:
            Cached or computed value
        """
        value = self.get(key)
        if value is not None:
            return value

        # Not in cache, compute
        computed = compute_func()
        self.put(key, computed, ttl)
        return computed

    def cleanup_expired(self) -> int:
        """
        Remove all expired entries.

        Returns:
            Number of entries removed
        """
        self._acquire_lock()
        try:
            expired_keys = [
                key for key, entry in self._cache.items()
                if entry.is_expired()
            ]

            for key in expired_keys:
                self._remove_entry(key)
                self._stats.expirations += 1

            return len(expired_keys)
        finally:
            self._release_lock()

    def keys(self) -> list:
        """Return list of cache keys (most recent last)."""
        self._acquire_lock()
        try:
            return list(self._cache.keys())
        finally:
            self._release_lock()

    def values(self) -> list:
        """Return list of cache values (most recent last)."""
        self._acquire_lock()
        try:
            return [entry.value for entry in self._cache.values()]
        finally:
            self._release_lock()

    def items(self) -> list:
        """Return list of (key, value) pairs (most recent last)."""
        self._acquire_lock()
        try:
            return [(k, e.value) for k, e in self._cache.items()]
        finally:
            self._release_lock()

    @property
    def stats(self) -> CacheStats:
        """Return cache statistics."""
        return self._stats

    @property
    def size(self) -> int:
        """Return current cache size."""
        return len(self._cache)

    @property
    def max_size(self) -> int:
        """Return maximum cache size."""
        return self._max_size

    def resize(self, new_max_size: int) -> None:
        """
        Resize cache, evicting entries if necessary.

        Args:
            new_max_size: New maximum size
        """
        self._acquire_lock()
        try:
            self._max_size = new_max_size
            while len(self._cache) > self._max_size:
                self._evict_lru()
        finally:
            self._release_lock()

    def get_entry_info(self, key: K) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a cache entry.

        Args:
            key: Cache key

        Returns:
            Dictionary with entry metadata or None
        """
        self._acquire_lock()
        try:
            if key not in self._cache:
                return None

            entry = self._cache[key]
            now = time.time()

            return {
                "created_at": entry.created_at,
                "accessed_at": entry.accessed_at,
                "age_seconds": now - entry.created_at,
                "ttl": entry.ttl,
                "time_remaining": (entry.created_at + entry.ttl - now) if entry.ttl else None,
                "hit_count": entry.hit_count,
                "is_expired": entry.is_expired(),
            }
        finally:
            self._release_lock()


class AsyncLRUCache(LRUCache[K, V]):
    """
    Async-compatible LRU Cache.

    Provides async versions of cache operations for use with asyncio.
    """

    async def aget(self, key: K, default: Optional[V] = None) -> Optional[V]:
        """Async version of get."""
        return self.get(key, default)

    async def aput(self, key: K, value: V, ttl: Optional[float] = None) -> None:
        """Async version of put."""
        self.put(key, value, ttl)

    async def aget_or_compute(self,
                              key: K,
                              compute_func: Callable[[], V],
                              ttl: Optional[float] = None) -> V:
        """Async version of get_or_compute."""
        value = self.get(key)
        if value is not None:
            return value

        # Support both sync and async compute functions
        import asyncio
        if asyncio.iscoroutinefunction(compute_func):
            computed = await compute_func()
        else:
            computed = compute_func()

        self.put(key, computed, ttl)
        return computed


# Convenience function for creating caches
def create_cache(max_size: int = 1000,
                 ttl: Optional[float] = None,
                 thread_safe: bool = True) -> LRUCache:
    """
    Create an LRU cache with common defaults.

    Args:
        max_size: Maximum entries
        ttl: Default TTL in seconds
        thread_safe: Enable thread safety

    Returns:
        Configured LRUCache instance
    """
    return LRUCache(
        max_size=max_size,
        default_ttl=ttl,
        thread_safe=thread_safe
    )


# Decorator for caching function results
def cached(max_size: int = 128,
           ttl: Optional[float] = None,
           key_func: Optional[Callable[..., str]] = None):
    """
    Decorator to cache function results.

    Args:
        max_size: Maximum cache size
        ttl: TTL for cached results
        key_func: Function to generate cache key from args

    Returns:
        Decorated function with caching
    """
    cache = LRUCache(max_size=max_size, default_ttl=ttl)

    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = str((args, tuple(sorted(kwargs.items()))))

            # Check cache
            result = cache.get(cache_key)
            if result is not None:
                return result

            # Compute and cache
            result = func(*args, **kwargs)
            cache.put(cache_key, result)
            return result

        wrapper.cache = cache  # Expose cache for inspection
        wrapper.cache_clear = cache.clear
        wrapper.cache_info = lambda: cache.stats.to_dict()
        return wrapper

    return decorator
