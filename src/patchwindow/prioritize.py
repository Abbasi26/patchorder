"""Priority points. The briefing prints this same formula."""

from __future__ import annotations

import math
from dataclasses import dataclass

KEV_POINTS = 40.0
EPSS_POINTS = 25.0
CVSS_POINTS = 20.0
EXPOSURE_POINTS = {"internet": 10.0, "internal": 4.0}
COUNT_POINTS = 5.0
CSAF_POINTS = 5.0
MAX_POINTS = KEV_POINTS + EPSS_POINTS + CVSS_POINTS + 10.0 + COUNT_POINTS + CSAF_POINTS

FORMULA_LINES = (
    f"priority points (maximum {MAX_POINTS:.0f}) =",
    f"  {KEV_POINTS:.0f} if the CVE is in the CISA KEV catalog loaded for this run, else 0",
    f"  + EPSS probability x {EPSS_POINTS:.0f} (0 when EPSS is missing)",
    f"  + CVSS base score / 10 x {CVSS_POINTS:.0f} (0 when CVSS is missing)",
    "  + 10 when exposure is internet, 4 when it is internal",
    "  + host-count points: min(5, log10(count + 1) / log10(1001) x 5)",
    "  + 5 when a loaded CSAF document marks this exact version known_affected for this CVE",
)


def _round(value: float) -> float:
    return round(value + 1e-9, 2)


@dataclass(frozen=True)
class ScorePart:
    points: float
    text: str


def count_points(count: int) -> float:
    if count <= 0:
        return 0.0
    raw = math.log10(count + 1) / math.log10(1001) * COUNT_POINTS
    return _round(min(COUNT_POINTS, raw))


def score(
    *,
    kev: bool,
    kev_detail: str,
    epss: float | None,
    cvss: float | None,
    exposure: str,
    count: int,
    csaf_exact: bool,
    csaf_detail: str,
) -> tuple[float, list[ScorePart]]:
    parts: list[ScorePart] = []
    if kev:
        parts.append(ScorePart(KEV_POINTS, f"+{KEV_POINTS:.2f}  listed in the CISA KEV catalog loaded for this run{kev_detail}"))
    else:
        parts.append(ScorePart(0.0, "+0.00  not listed in the KEV catalog loaded for this run"))
    if epss is None:
        parts.append(ScorePart(0.0, "+0.00  EPSS missing"))
        epss_points = 0.0
    else:
        epss_points = _round(epss * EPSS_POINTS)
        parts.append(ScorePart(epss_points, f"+{epss_points:.2f}  EPSS {epss:.5f} (probability x {EPSS_POINTS:.0f})"))
    if cvss is None:
        parts.append(ScorePart(0.0, "+0.00  CVSS missing"))
        cvss_points = 0.0
    else:
        cvss_points = _round(cvss / 10 * CVSS_POINTS)
        parts.append(ScorePart(cvss_points, f"+{cvss_points:.2f}  CVSS {cvss:.1f} (score / 10 x {CVSS_POINTS:.0f})"))
    exposure_points = EXPOSURE_POINTS.get(exposure, 0.0)
    parts.append(ScorePart(exposure_points, f"+{exposure_points:.2f}  exposure {exposure}"))
    hosts = count_points(count)
    parts.append(ScorePart(hosts, f"+{hosts:.2f}  {count} hosts (log10(count + 1) / log10(1001) x 5, capped at 5)"))
    if csaf_exact:
        parts.append(ScorePart(CSAF_POINTS, f"+{CSAF_POINTS:.2f}  CSAF marks this exact version known_affected ({csaf_detail})"))
    else:
        parts.append(ScorePart(0.0, "+0.00  no loaded CSAF document marks this exact version known_affected"))
    total = _round(sum(part.points for part in parts))
    return total, parts
