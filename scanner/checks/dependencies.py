"""Dependency hygiene: unpinned versions, and (optionally, online) known
public advisories against pinned versions.

Two separate checks share this module because they share the same parsing:

- UnpinnedDependencyCheck (PCAT-DEP-UNPINNED): flags any requirement that
  isn't pinned to an exact version. Offline, always runs.
- VulnerableDependencyCheck (PCAT-DEP-VULN): takes every exactly-pinned
  requirement and batch-queries osv.dev, a public vulnerability database,
  for known advisories. Off by default — only runs with --online — so a
  plain scan never depends on network access or third-party service
  availability. Querying osv.dev about a package name/version is not
  scanning anyone's infrastructure, so it doesn't conflict with the
  own-systems-only scope stated in the README.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path

from scanner.checks.base import Check, make_finding
from scanner.finding import Finding
from scanner.util import iter_files, read_text_safe

UNPINNED_CHECK_ID = "PCAT-DEP-UNPINNED"
VULN_CHECK_ID = "PCAT-DEP-VULN"

OSV_API_URL = "https://api.osv.dev/v1/querybatch"
OSV_TIMEOUT_SECONDS = 5.0

_PINNED_RE = re.compile(r"^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9.\-+]+)")


def _parse_requirements_txt(text: str) -> list[tuple[int, str]]:
    """Return (line_number, requirement_line) for each real requirement line."""
    out = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        out.append((lineno, stripped))
    return out


class UnpinnedDependencyCheck(Check):
    check_id = UNPINNED_CHECK_ID

    def run(self, target: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in iter_files(target):
            if path.name != "requirements.txt":
                continue
            text = read_text_safe(path)
            if text is None:
                continue
            rel = path.relative_to(target)
            for lineno, req in _parse_requirements_txt(text):
                if not _PINNED_RE.match(req):
                    findings.append(
                        make_finding(
                            UNPINNED_CHECK_ID,
                            affected_asset=str(rel),
                            evidence=f"Requirement not pinned to an exact version: `{req}`",
                            line=lineno,
                        )
                    )
        return findings


class VulnerableDependencyCheck(Check):
    check_id = VULN_CHECK_ID

    def __init__(self, offline: bool = True, timeout: float = OSV_TIMEOUT_SECONDS):
        self.offline = offline
        self.timeout = timeout

    def run(self, target: Path) -> list[Finding]:
        if self.offline:
            return []

        packages: list[tuple[Path, int, str, str]] = []
        for path in iter_files(target):
            if path.name != "requirements.txt":
                continue
            text = read_text_safe(path)
            if text is None:
                continue
            for lineno, req in _parse_requirements_txt(text):
                match = _PINNED_RE.match(req)
                if match:
                    packages.append((path, lineno, match.group(1), match.group(2)))

        if not packages:
            return []

        queries = [
            {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
            for _, _, name, version in packages
        ]
        try:
            body = json.dumps({"queries": queries}).encode("utf-8")
            request = urllib.request.Request(
                OSV_API_URL,
                data=body,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.loads(response.read())
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            # Network optional by design: a failed advisory lookup should
            # degrade to "no vulnerable-dependency findings", not crash the
            # rest of the scan.
            return []

        findings: list[Finding] = []
        for (path, lineno, name, version), result in zip(packages, data.get("results", [])):
            vulns = result.get("vulns", [])
            if not vulns:
                continue
            ids = ", ".join(v.get("id", "?") for v in vulns[:5])
            rel = path.relative_to(target)
            findings.append(
                make_finding(
                    VULN_CHECK_ID,
                    affected_asset=str(rel),
                    evidence=f"{name}=={version} — public advisories: {ids}",
                    line=lineno,
                )
            )
        return findings
