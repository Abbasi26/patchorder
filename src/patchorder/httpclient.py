"""Rate-limited HTTP. One User-Agent, no telemetry, Retry-After honored once."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit

from patchorder import __version__
from patchorder.cache import Cache
from patchorder.errors import PatchorderError

# Public NVD limit without a key is 5 requests per 30 seconds. Vulnerability-Lookup
# anonymous limit is 20 per minute. Stay under both.
HOST_INTERVALS = (
    ("services.nvd.nist.gov", 6.5),
    ("vulnerability.circl.lu", 3.5),
    ("api.first.org", 1.0),
    ("www.cisa.gov", 1.0),
    ("wid.cert-bund.de", 1.0),
)

TTL_SECONDS = {
    "kev": 24 * 3600,
    "epss": 24 * 3600,
    "nvd-cve": 12 * 3600,
    "nvd-cpe": 7 * 24 * 3600,
    "vulnlookup": 12 * 3600,
    "csaf-meta": 24 * 3600,
}


def user_agent(contact: str | None = None) -> str:
    import os

    who = contact or os.environ.get("PATCHORDER_CONTACT") or "local; no telemetry"
    return f"patchorder/{__version__} ({who})"


@dataclass
class HttpResult:
    status: int
    headers: dict[str, str]
    body: bytes


class RateLimiter:
    def __init__(self, sleep=time.sleep, now=time.monotonic) -> None:
        self.sleep = sleep
        self.now = now
        self._next: dict[str, float] = {}

    def wait(self, url: str) -> None:
        host = urlsplit(url).netloc
        interval = 0.0
        for suffix, seconds in HOST_INTERVALS:
            if host == suffix or host.endswith("." + suffix):
                interval = seconds
                break
        if interval <= 0:
            return
        current = self.now()
        earliest = self._next.get(host, current)
        if earliest > current:
            delay = min(120.0, earliest - current)
            self.sleep(delay)
            current = self.now()
        self._next[host] = current + interval


def urllib_opener(url: str, headers: dict[str, str], timeout: float = 45.0) -> HttpResult:
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return HttpResult(response.status, {k.lower(): v for k, v in response.headers.items()}, response.read())
    except urllib.error.HTTPError as exc:
        body = exc.read()
        return HttpResult(exc.code, {k.lower(): v for k, v in exc.headers.items()}, body)


class HttpClient:
    def __init__(
        self,
        cache: Cache,
        *,
        offline: bool = False,
        refresh: bool = False,
        opener=None,
        limiter: RateLimiter | None = None,
        contact: str | None = None,
        sleep=time.sleep,
    ) -> None:
        self.cache = cache
        self.offline = offline
        self.refresh = refresh
        self.opener = opener or urllib_opener
        self.limiter = limiter or RateLimiter(sleep=sleep)
        self.contact = contact
        self.sleep = sleep
        self.calls = 0

    def get_json(self, url: str, kind: str) -> dict:
        ttl = TTL_SECONDS.get(kind, 12 * 3600)
        if not self.refresh:
            cached = self.cache.get(url, ttl)
            if cached is not None:
                return cached
        if self.offline:
            raise PatchorderError(
                f"offline mode has no cached response for {url.split('?')[0]}",
                code=3,
            )
        payload, _status = self._fetch(url)
        if not isinstance(payload, dict):
            raise PatchorderError(f"response was not a JSON object from {urlsplit(url).netloc}")
        self.cache.put(url, payload)
        return payload

    def _fetch(self, url: str, retried: bool = False) -> tuple[dict, int]:
        self.limiter.wait(url)
        headers = {"User-Agent": user_agent(self.contact), "Accept": "application/json"}
        self.calls += 1
        try:
            result = self.opener(url, headers)
        except PatchorderError:
            raise
        except Exception as exc:
            raise PatchorderError(f"request failed for {urlsplit(url).netloc}: {exc}") from exc
        if result.status == 429 and not retried:
            retry = result.headers.get("retry-after", "30")
            try:
                delay = min(120.0, float(retry))
            except ValueError:
                delay = 30.0
            self.sleep(delay)
            return self._fetch(url, retried=True)
        if result.status == 404:
            return {}, 404
        if result.status != 200:
            raise PatchorderError(f"{urlsplit(url).netloc} returned HTTP {result.status}")
        try:
            payload = json.loads(result.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PatchorderError(f"response from {urlsplit(url).netloc} was not JSON") from exc
        if not isinstance(payload, dict):
            raise PatchorderError(f"response from {urlsplit(url).netloc} was not a JSON object")
        return payload, result.status
