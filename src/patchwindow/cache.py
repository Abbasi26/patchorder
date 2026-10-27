"""Local JSON cache. Keys ignore NVD apiKey query parameters."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from patchwindow.errors import PatchwindowError


def cache_key(url: str) -> str:
    parts = urlsplit(url)
    query = [(key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True) if key.lower() != "apikey"]
    safe = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))
    return hashlib.sha256(safe.encode("utf-8")).hexdigest()


class Cache:
    def __init__(self, root: Path) -> None:
        self.root = root

    def _path(self, url: str) -> Path:
        return self.root / f"{cache_key(url)}.json"

    def get(self, url: str, ttl_seconds: int, now: float | None = None) -> dict | None:
        path = self._path(url)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PatchwindowError(f"cache entry is unreadable ({path.name}). Delete {self.root} or pass --refresh.") from exc
        fetched = float(payload.get("fetched_at") or 0)
        current = time.time() if now is None else now
        if ttl_seconds >= 0 and current - fetched > ttl_seconds:
            return None
        body = payload.get("body")
        if not isinstance(body, dict):
            return None
        return body

    def put(self, url: str, body: dict, now: float | None = None) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        parts = urlsplit(url)
        query = [(key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True) if key.lower() != "apikey"]
        stored_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))
        payload = {
            "url": stored_url,
            "fetched_at": time.time() if now is None else now,
            "body": body,
        }
        path = self._path(url)
        path.write_text(json.dumps(payload), encoding="utf-8")
