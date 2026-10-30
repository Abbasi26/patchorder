"""Exit-code gates for CI and scheduled jobs. The briefing is printed either way."""

from __future__ import annotations

from dataclasses import dataclass

from patchorder.errors import PatchorderError
from patchorder.report import Report

GATE_EXIT = 4


@dataclass(frozen=True)
class Gate:
    kind: str
    threshold: float | None = None

    def label(self) -> str:
        if self.threshold is not None:
            return f"{self.kind}:{self.threshold:g}"
        return self.kind


def parse_gate(text: str) -> Gate:
    value = text.strip().lower()
    if value in {"kev", "new", "internet"}:
        return Gate(value)
    if value.startswith("priority:"):
        try:
            threshold = float(value.split(":", 1)[1])
        except ValueError as exc:
            raise PatchorderError(f"--fail-on {text}: priority needs a number, for example priority:70", code=2) from exc
        if not 0 <= threshold <= 105:
            raise PatchorderError(f"--fail-on {text}: priority is between 0 and 105", code=2)
        return Gate("priority", threshold)
    if value.startswith("epss:"):
        try:
            threshold = float(value.split(":", 1)[1])
        except ValueError as exc:
            raise PatchorderError(f"--fail-on {text}: epss needs a probability, for example epss:0.5", code=2) from exc
        if not 0 <= threshold <= 1:
            raise PatchorderError(f"--fail-on {text}: epss is a probability between 0 and 1", code=2)
        return Gate("epss", threshold)
    raise PatchorderError(f"--fail-on {text}: use kev, new, internet, priority:N, or epss:N", code=2)


def evaluate_gates(report: Report, gates: list[Gate]) -> list[str]:
    """Return one line per tripped gate. An empty list means pass."""
    tripped: list[str] = []
    for gate in gates:
        if gate.kind == "kev":
            hits = [f for f in report.findings if f.kev]
        elif gate.kind == "internet":
            hits = [f for f in report.findings if f.exposure == "internet"]
        elif gate.kind == "priority":
            hits = [f for f in report.findings if f.points >= (gate.threshold or 0)]
        elif gate.kind == "epss":
            hits = [f for f in report.findings if f.epss is not None and f.epss >= (gate.threshold or 0)]
        elif gate.kind == "new":
            if report.new_cve_ids is None:
                raise PatchorderError("--fail-on new needs --state with a previous run's state file", code=2)
            new = set(report.new_cve_ids)
            hits = [f for f in report.findings if f.cve_id in new]
        else:  # pragma: no cover - parse_gate rejects other kinds
            continue
        if hits:
            pairs = sorted({f"{f.asset_id}:{f.cve_id}" for f in hits})
            shown = ", ".join(pairs[:5]) + (f" and {len(pairs) - 5} more" if len(pairs) > 5 else "")
            tripped.append(f"--fail-on {gate.label()}: {len(pairs)} finding(s) ({shown})")
    return tripped
