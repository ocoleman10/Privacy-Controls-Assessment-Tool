"""Core data model: a Finding is the unit the whole tool produces and reports on.

The shape is deliberately the consulting deliverable shape, not a linter's
shape: finding ID, severity, affected asset, control reference(s), evidence,
remediation, and an estimated remediation effort. See controls/catalog.py for
where control references and remediation text actually come from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

    @property
    def rank(self) -> int:
        """Lower rank sorts first (most severe first)."""
        return {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}[self.value]


@dataclass(frozen=True)
class ControlRef:
    """One control-catalog reference, e.g. NIST CSF 2.0 PR.AA-05."""

    framework: str
    ref_id: str
    title: str

    def __str__(self) -> str:
        return f"{self.framework} {self.ref_id} — {self.title}"


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    affected_asset: str
    evidence: str
    control_refs: list[ControlRef]
    remediation: str
    estimated_effort: str
    line: int | None = None
    # Assigned by the engine after all checks run and findings are sorted,
    # so IDs are stable/sequential in the final report rather than per-check.
    finding_id: str = field(default="")
