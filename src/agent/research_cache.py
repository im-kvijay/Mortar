"""module docstring"""

import json
import hashlib
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime


class ResearchCache:
    """
    JIT research cache

    Simple key-value store backed by JSON file.

    Features:
    - Persistent storage (JSON)
    - Auto-save on updates
    - Hit count tracking
    - Cache statistics
    """

    def __init__(self, cache_file: Optional[str] = None):
        """
        Initialize research cache

        Args:
            cache_file: Path to cache file (uses config.JIT_CACHE_FILE if None)
        """
        if cache_file is None:
            from config import config
            cache_file = str(config.JIT_CACHE_FILE)
        self.cache_file = Path(cache_file)
        self.cache = {}

        # ensure cache directory exists
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)

        # load existing cache
        self._load()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Get cached response

        Args:
            key: Cache key

        Returns:
            Cached response or None if not found
        """
        if key in self.cache:
            # increment hit count
            self.cache[key]["hit_count"] = self.cache[key].get("hit_count", 0) + 1
            self.cache[key]["last_accessed"] = datetime.now().isoformat()

            # auto-save (track hit count)
            self._save()

            return self.cache[key]

        return None

    def set(self, key: str, value: Dict[str, Any]):
        """
        Set cached response

        Args:
            key: Cache key
            value: Response to cache
        """
        # add metadata
        value["timestamp"] = datetime.now().isoformat()
        value["hit_count"] = 0

        self.cache[key] = value

        # auto-save
        self._save()

    def make_key(self, question: str, specialist_type: str) -> str:
        """
        Generate cache key from question and specialist type

        Normalizes question:
        - Lowercase
        - Strip whitespace
        - Hash for consistent length

        Args:
            question: Research question
            specialist_type: Specialist type

        Returns:
            Cache key
        """
        # normalize question
        normalized = question.lower().strip()

        # create key: specialist_type:question_hash
        question_hash = hashlib.md5(normalized.encode()).hexdigest()[:16]

        return f"{specialist_type}:{question_hash}"

    def clear(self):
        """
        Clear all cache entries
        """
        self.cache = {}
        self._save()

    def stats(self) -> Dict[str, Any]:
        """
        Get cache statistics

        Returns:
            Stats dict with size, hit counts, etc
        """
        total_hits = sum(entry.get("hit_count", 0) for entry in self.cache.values())
        total_entries = len(self.cache)

        specialist_counts = {}
        for entry in self.cache.values():
            specialist = entry.get("specialist_type", "unknown")
            specialist_counts[specialist] = specialist_counts.get(specialist, 0) + 1

        return {
            "total_entries": total_entries,
            "total_hits": total_hits,
            "avg_hits_per_entry": total_hits / total_entries if total_entries > 0 else 0,
            "specialist_breakdown": specialist_counts,
            "cache_file": str(self.cache_file),
            "file_size_kb": self.cache_file.stat().st_size / 1024 if self.cache_file.exists() else 0
        }

    def export(self, export_path: str):
        """
        Export cache to another file

        Args:
            export_path: Destination path
        """
        export_file = Path(export_path)
        export_file.parent.mkdir(parents=True, exist_ok=True)

        with open(export_file, 'w') as f:
            json.dump(self.cache, f, indent=2)

    def import_cache(self, import_path: str, merge: bool = True):
        """
        Import cache from another file

        Args:
            import_path: Source path
            merge: If True, merge with existing cache; if False, replace
        """
        import_file = Path(import_path)

        if not import_file.exists():
            raise FileNotFoundError(f"Import file not found: {import_path}")

        with open(import_file, 'r') as f:
            imported = json.load(f)

        if merge:
            # merge: keep existing entries, add new ones
            self.cache.update(imported)
        else:
            # replace
            self.cache = imported

        self._save()

    def _load(self):
        """
        Load cache from file
        """
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'r') as f:
                    self.cache = json.load(f)
            except Exception as e:
                print(f"[Cache] Error loading cache: {e}")
                self.cache = {}
        else:
            self.cache = {}

    def _save(self):
        """
        Save cache to file
        """
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            print(f"[Cache] Error saving cache: {e}")

    def __len__(self):
        """
        Number of cached entries
        """
        return len(self.cache)

    def __contains__(self, key: str):
        """
        Check if key exists in cache
        """
        return key in self.cache
