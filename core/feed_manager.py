"""
Feed Manager — loads and queries external threat intelligence data feeds.
Add your own feeds in feeds/examples/ or create custom BaseFeed subclasses.
"""

import importlib
import os
import sys
from typing import Any


class FeedManager:
    """Discovers and manages all registered data feeds."""

    def __init__(self):
        self._feeds: dict[str, Any] = {}
        self._load_feeds()

    def _load_feeds(self):
        feeds_dir = os.path.join(os.path.dirname(__file__), "..", "feeds")
        feeds_dir = os.path.abspath(feeds_dir)
        sys.path.insert(0, feeds_dir)

        for root, _, files in os.walk(feeds_dir):
            for fname in files:
                if fname.endswith(".py") and not fname.startswith("_"):
                    module_path = os.path.join(root, fname)
                    module_name = fname[:-3]
                    try:
                        spec = importlib.util.spec_from_file_location(module_name, module_path)
                        mod = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(mod)
                        if hasattr(mod, "FEED_NAME") and hasattr(mod, "query"):
                            self._feeds[mod.FEED_NAME] = mod
                    except Exception:
                        pass  # Skip broken feeds gracefully

    def query_all(self, indicator: str) -> dict[str, Any]:
        """Query all loaded feeds for the given indicator (IP, hash, domain, etc.)."""
        results = {}
        for name, feed in self._feeds.items():
            try:
                results[name] = feed.query(indicator)
            except Exception as e:
                results[name] = {"error": str(e)}
        return results

    def query_feed(self, feed_name: str, indicator: str) -> Any:
        """Query a specific feed by name."""
        if feed_name not in self._feeds:
            raise KeyError(f"Feed '{feed_name}' not found. Available: {list(self._feeds.keys())}")
        return self._feeds[feed_name].query(indicator)

    @property
    def available_feeds(self) -> list[str]:
        return list(self._feeds.keys())
