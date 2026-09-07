"""Missing or disabled encryption controls.

Heuristic, config-file-oriented: rather than trying to prove a data store
actually encrypts at rest (out of reach for a static scan), this looks for
explicit signals that encryption has been turned OFF or a connection is
deliberately unencrypted — the kind of thing a developer writes for local
convenience and forgets to gate behind an environment check.

Covers both data-in-transit (disabled TLS/SSL flags) and data-at-rest
(explicit encryption-disabled flags), which is why PCAT-ENCRYPT cites both
PR.DS-01 and PR.DS-02 in the catalog rather than picking one.
"""

from __future__ import annotations

import re
from pathlib import Path

from scanner.checks.base import Check, make_finding
from scanner.finding import Finding
from scanner.util import iter_text_files, read_text_safe

CHECK_ID = "PCAT-ENCRYPT"

_INSECURE_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "TLS/SSL explicitly disabled on a database connection",
        re.compile(r"(?i)sslmode\s*=\s*disable"),
    ),
    (
        "TLS/SSL/encryption flag explicitly set to false/off",
        re.compile(r"(?i)\b(useSSL|use_ssl|ssl|tls|encrypt(ion)?)\b\s*[:=]\s*(false|0|off|none)\b"),
    ),
    (
        "Plaintext HTTP endpoint referencing a data/auth service",
        re.compile(r"(?i)\bhttp://[^\s'\"]*\b(db|database|api|auth|token|secret)[^\s'\"]*"),
    ),
]


class EncryptionAtRestCheck(Check):
    check_id = CHECK_ID

    def run(self, target: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in iter_text_files(target):
            text = read_text_safe(path)
            if text is None:
                continue
            rel = path.relative_to(target)
            for lineno, line in enumerate(text.splitlines(), start=1):
                for label, pattern in _INSECURE_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        findings.append(
                            make_finding(
                                CHECK_ID,
                                affected_asset=str(rel),
                                evidence=f"{label}: `{match.group(0).strip()}`",
                                line=lineno,
                            )
                        )
        return findings
