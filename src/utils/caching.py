"""caching utilities provides thread-safe caching implementations for the mortar-c agent system. cla..."""

import threading
from collections import OrderedDict
from typing import Any, Optional


class LRUCache:
    """simple lru cache implementation with max size limit. used to prevent unbounded memory growth in j..."""

    def __init__(self, maxsize: int = 1000):
        """initialize lru cache args: maxsize: maximum cache size (default: 1000)"""
        self.maxsize = maxsize
        self._cache = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        """get value from cache, updating access order args: key: cache key returns: cached value or none if..."""
        with self._lock:
            if key in self._cache:
#                # move to end (most recently used)
                self._cache.move_to_end(key)
                return self._cache[key]
            return None

    def put(self, key: str, value: Any) -> None:
        """put value in cache, evicting oldest if necessary args: key: cache key value: value to cache"""
        with self._lock:
            if key in self._cache:
#                # update existing entry and move to end
                self._cache.move_to_end(key)
                self._cache[key] = value
            else:
#                # add new entry
                if len(self._cache) >= self.maxsize:
#                    # evict oldest (first item)
                    self._cache.popitem(last=False)
                self._cache[key] = value

    def clear(self) -> None:
        """clear all cache entries"""
        with self._lock:
            self._cache.clear()
