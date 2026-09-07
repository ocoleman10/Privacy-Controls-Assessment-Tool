"""Base class every check implements, plus a helper to build a Finding
from the control catalog so checks never hardcode their own control refs,
severity, remediation text, or effort estimate — that all comes from one
place: controls/catalog.py."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from controls.catalog import CATALOG
from scanner.finding import Finding


class Check(ABC):
    check_id: str

    @abstractmethod
    def run(self, target: Path) -> list[Finding]:
        """Scan target and return any findings this check produces."""
        raise NotImplementedError


def make_finding(check_id: str, affected_asset: str, evidence: str, line: int | None = None) -> Finding:
    meta = CATALOG[check_id]
    return Finding(
        check_id=check_id,
        title=meta.title,
        severity=meta.default_severity,
        affected_asset=affected_asset,
        evidence=evidence,
        control_refs=list(meta.control_refs),
        remediation=meta.remediation,
        estimated_effort=meta.estimated_effort,
        line=line,
    )
