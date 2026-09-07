"""Wires every check together into a single scan.

Running order doesn't matter for correctness — findings are sorted by
severity (then asset, then line) after every check has run, and finding IDs
are assigned only at that point, so the report's PCAT-0001, PCAT-0002, ...
numbering is stable and severity-ordered regardless of which check happened
to run first.
"""

from __future__ import annotations

from pathlib import Path

from scanner.checks.dependencies import UnpinnedDependencyCheck, VulnerableDependencyCheck
from scanner.checks.encryption import EncryptionAtRestCheck
from scanner.checks.env_files import EnvFileCheck
from scanner.checks.permissions import PermissionsCheck
from scanner.checks.pii_logs import PiiInLogsCheck
from scanner.checks.secrets import HardcodedSecretsCheck
from scanner.finding import Finding


def default_checks(online: bool = False) -> list:
    return [
        HardcodedSecretsCheck(),
        EnvFileCheck(),
        PiiInLogsCheck(),
        UnpinnedDependencyCheck(),
        VulnerableDependencyCheck(offline=not online),
        PermissionsCheck(),
        EncryptionAtRestCheck(),
    ]


def run_scan(target: Path, checks: list | None = None, online: bool = False) -> list[Finding]:
    if checks is None:
        checks = default_checks(online=online)

    findings: list[Finding] = []
    for check in checks:
        findings.extend(check.run(target))

    findings.sort(key=lambda f: (f.severity.rank, f.affected_asset, f.line or 0))
    for index, finding in enumerate(findings, start=1):
        finding.finding_id = f"PCAT-{index:04d}"

    return findings
