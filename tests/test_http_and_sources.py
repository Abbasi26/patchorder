import json
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from patchorder.cache import Cache, cache_key
from patchorder.engine import live_scan, resolve_inventory
from patchorder.httpclient import HttpClient, HttpResult, RateLimiter
from patchorder.inventory import load_inventory
from patchorder.lockfile import load_lock
from patchorder.sources import NVD_PAGE_SIZE, LiveFetcher, epss_url, nvd_cve_url

ROOT = Path(__file__).resolve().parents[1] / "src" / "patchorder" / "data" / "demo"


class Clock:
    def __init__(self):
        self.now = 0.0
        self.slept = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def test_rate_limiter_spaces_nvd_calls():
    clock = Clock()
    limiter = RateLimiter(sleep=clock.sleep, now=clock.monotonic)
    limiter.wait("https://services.nvd.nist.gov/rest/json/cves/2.0?x=1")
    limiter.wait("https://services.nvd.nist.gov/rest/json/cves/2.0?x=2")
    assert clock.slept == [6.5]


def test_cache_strips_api_keys(tmp_path):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe&apiKey=super-secret"
    cache = Cache(tmp_path)
    cache.put(url, {"ok": True}, now=1)
    stored = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    assert "super-secret" not in json.dumps(stored)
    assert cache.get(url, ttl_seconds=10, now=2) == {"ok": True}
    assert cache_key(url) == cache_key("https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe")


def test_live_scan_uses_cache_and_does_not_call_the_network_twice(tmp_path, monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    calls = []

    def opener(url, headers):
        calls.append(url)
        assert "patchorder/" in headers["User-Agent"]
        assert "apiKey" not in url
        if "cpes/2.0" in url:
            body = (ROOT / "nvd-cpes-nginx.json").read_bytes()
        elif "cves/2.0" in url:
            body = (ROOT / "nvd" / "CVE-2023-44487.json").read_bytes()
        elif "cpesearch" in url:
            body = b'{"nvd": []}'
        elif "known_exploited" in url:
            body = (ROOT / "kev.json").read_bytes()
        elif "api.first.org" in url:
            body = (ROOT / "epss.json").read_bytes()
        else:
            raise AssertionError(url)
        return HttpResult(200, {"content-type": "application/json"}, body)

    inventory = load_inventory(ROOT / "inventory.yaml")
    # One pinned nginx row is enough to prove the live path. The full demo would
    # fan out to every version; this keeps the fake clock honest.
    inventory.assets = [asset for asset in inventory.assets if asset.id == "edge-proxy"]
    lock = load_lock(ROOT / "inventory.lock.yaml")
    clock = Clock()
    client = HttpClient(
        Cache(tmp_path / "cache"),
        opener=opener,
        limiter=RateLimiter(sleep=clock.sleep, now=clock.monotonic),
        sleep=clock.sleep,
    )
    fetcher = LiveFetcher(client)
    resolutions = resolve_inventory(inventory, lock)
    report = live_scan(inventory, resolutions, fetcher, [], None, pinned_only=False)
    assert report.findings[0].cve_id == "CVE-2023-44487"
    assert report.findings[0].kev
    assert any("1.25.2" in url or "1.25.2" in url.replace("%3A", ":") for url in calls)
    first_calls = len(calls)
    assert first_calls >= 3
    client.offline = True
    client.refresh = False
    report_again = live_scan(inventory, resolutions, fetcher, [], None, pinned_only=False)
    assert report_again.findings[0].cve_id == "CVE-2023-44487"
    assert len(calls) == first_calls
    built = nvd_cve_url("cpe:2.3:a:f5:nginx", "1.25.2")
    assert "1.25.2" in built
    assert "api.first.org" in epss_url(["CVE-2023-44487"])


def test_retry_after_is_honored_once(tmp_path):
    clock = Clock()
    seen = {"n": 0}

    def opener(url, headers):
        seen["n"] += 1
        if seen["n"] == 1:
            return HttpResult(429, {"retry-after": "2"}, b"")
        return HttpResult(200, {}, b'{"data": []}')

    client = HttpClient(
        Cache(tmp_path),
        opener=opener,
        limiter=RateLimiter(sleep=clock.sleep, now=clock.monotonic),
        sleep=clock.sleep,
    )
    payload = client.get_json("https://api.first.org/data/v1/epss?cve=CVE-2024-0001", "epss")
    assert payload == {"data": []}
    assert seen["n"] == 2
    assert 2 in clock.slept


class _PagingNvd:
    """NVD stand-in. Page size and totalResults come from the response, as they do live."""

    def __init__(
        self,
        total: int,
        pages: dict[tuple[int, bool], list[tuple[str, str]]],
        per_page: int | None = None,
    ):
        self.total = total
        self.pages = pages
        self.per_page = per_page
        self.urls: list[str] = []

    def get_json(self, url: str, kind: str) -> dict:
        self.urls.append(url)
        query = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
        start = int(query.get("startIndex", "0"))
        has_kev = "hasKev" in query
        per_page = self.per_page if self.per_page is not None else int(query.get("resultsPerPage", str(NVD_PAGE_SIZE)))
        vulns = []
        for cve_id, status in self.pages.get((start, has_kev), []):
            vulns.append(
                {
                    "cve": {
                        "id": cve_id,
                        "vulnStatus": status,
                        "descriptions": [{"lang": "en", "value": cve_id}],
                    }
                }
            )
        return {
            "resultsPerPage": per_page,
            "startIndex": start,
            "totalResults": self.total,
            "vulnerabilities": vulns,
        }


def _starts(urls: list[str]) -> list[tuple[int, bool]]:
    found = []
    for url in urls:
        query = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
        found.append((int(query["startIndex"]), "hasKev" in query))
    return found


def test_nvd_walk_is_complete_when_rejected_cves_are_dropped():
    client = _PagingNvd(
        total=2,
        pages={(0, False): [("CVE-2000-0001", "Rejected"), ("CVE-2024-0001", "Analyzed")]},
    )
    warnings: list[str] = []
    records = LiveFetcher(client, max_pages=1)._nvd_cves("cpe:2.3:a:f5:nginx", "1.25.2", warnings)
    assert [record.cve_id for record in records] == ["CVE-2024-0001"]
    assert warnings == []
    assert _starts(client.urls) == [(0, False)]


def test_nvd_walk_continues_past_a_page_of_only_rejected_cves():
    client = _PagingNvd(
        total=2,
        per_page=1,
        pages={
            (0, False): [("CVE-2000-0001", "Rejected")],
            (1, False): [("CVE-2024-0002", "Analyzed")],
        },
    )
    warnings: list[str] = []
    records = LiveFetcher(client, max_pages=2)._nvd_cves("cpe:2.3:a:openssl:openssl", "3.0.12", warnings)
    assert [record.cve_id for record in records] == ["CVE-2024-0002"]
    assert warnings == []
    assert _starts(client.urls) == [(0, False), (1, False)]


def test_nvd_large_result_keeps_newest_page_and_kev_subset():
    # 5000 results, two pages of 2000: the middle stays unloaded.
    client = _PagingNvd(
        total=5000,
        pages={
            (0, False): [("CVE-2009-0001", "Analyzed")],
            (2000, False): [("CVE-2016-0001", "Analyzed")],
            (3000, False): [("CVE-2024-9999", "Analyzed")],
            (0, True): [("CVE-2023-44487", "Analyzed")],
        },
    )
    warnings: list[str] = []
    records = LiveFetcher(client, max_pages=2)._nvd_cves(
        "cpe:2.3:o:microsoft:windows_server_2022", "10.0.20348.2400", warnings
    )
    assert [record.cve_id for record in records] == [
        "CVE-2009-0001",
        "CVE-2016-0001",
        "CVE-2024-9999",
        "CVE-2023-44487",
    ]
    assert _starts(client.urls) == [(0, False), (2000, False), (3000, False), (0, True)]
    assert len(warnings) == 1
    assert "5000" in warnings[0]
    assert "hasKev" in warnings[0]
    assert "middle" in warnings[0]


def test_nvd_window_of_two_pages_covers_a_windows_sized_result():
    client = _PagingNvd(
        total=3160,
        pages={
            (0, False): [("CVE-2021-26414", "Analyzed")],
            (2000, False): [("CVE-2024-38063", "Analyzed")],
        },
    )
    warnings: list[str] = []
    records = LiveFetcher(client, max_pages=2)._nvd_cves(
        "cpe:2.3:o:microsoft:windows_server_2022", "10.0.20348.2400", warnings
    )
    assert [record.cve_id for record in records] == ["CVE-2021-26414", "CVE-2024-38063"]
    assert warnings == []
    assert _starts(client.urls) == [(0, False), (2000, False)]


def test_nvd_single_page_still_fetches_the_unaligned_newest_start():
    client = _PagingNvd(
        total=3160,
        pages={
            (0, False): [("CVE-2021-26414", "Analyzed")],
            (1160, False): [("CVE-2024-38063", "Analyzed")],
            (0, True): [("CVE-2023-44487", "Analyzed")],
        },
    )
    warnings: list[str] = []
    records = LiveFetcher(client, max_pages=1)._nvd_cves(
        "cpe:2.3:o:microsoft:windows_server_2022", "10.0.20348.2400", warnings
    )
    assert "CVE-2024-38063" in [record.cve_id for record in records]
    assert _starts(client.urls) == [(0, False), (1160, False), (0, True)]
    assert warnings and "3160" in warnings[0]
