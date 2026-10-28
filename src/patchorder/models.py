"""Inventory rows, CPE candidates, and normalized vulnerability records."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Asset:
    id: str
    product: str
    vendor: str
    version: str
    count: int
    owner: str
    exposure: str


@dataclass
class Inventory:
    name: str
    assets: list[Asset]
    source: str


@dataclass(frozen=True)
class Candidate:
    cpe: str
    confidence: float
    origin: str
    note: str


@dataclass
class LockEntry:
    cpe: str
    pinned: bool = True
    confidence: float = 1.0
    origin: str = "user"
    note: str = ""


@dataclass
class Resolution:
    asset: Asset
    candidates: list[Candidate]
    chosen: Candidate | None
    confirmed: bool
    hint: str = ""


@dataclass
class Record:
    cve_id: str
    description: str
    configurations: list[dict]
    cve5_affected: list[dict]
    cvss: float | None
    severity: str | None
    vector: str | None
    references: list[str] = field(default_factory=list)
    published: str | None = None
    cisa_exploit_add: str | None = None
    cisa_name: str | None = None
    source: str = "nvd"


@dataclass
class EpssScore:
    cve_id: str
    probability: float
    percentile: float | None
    date: str | None


@dataclass
class KevEntry:
    cve_id: str
    name: str
    date_added: str | None
    short_description: str
    ransomware: str | None = None


@dataclass
class KevCatalog:
    title: str
    catalog_version: str
    date_released: str | None
    published_count: int | None
    entries: dict[str, KevEntry]
    note: str = ""
