"""PII written to logs.

Two detection modes on any line that looks like a logging/print call:

1. A literal PII-shaped value appears directly in the line (SSN, credit card,
   email) — high-confidence, this is PII in the source itself.
2. A variable with a PII-suggestive name is interpolated into the call
   (e.g. `logger.info(f"processing {ssn}")`) — the more realistic pattern in
   real code, since actual PII values rarely appear as source literals but
   the fields carrying them do get logged.
"""

from __future__ import annotations

import re
from pathlib import Path

from scanner.checks.base import Check, make_finding
from scanner.finding import Finding
from scanner.util import iter_text_files, read_text_safe, relative_asset_path

CHECK_ID = "PCAT-PII-LOG"

_LOG_CALL_RE = re.compile(r"\b(print|log(ger)?\.(debug|info|warning|warn|error|critical|exception))\s*\(")

_PII_LITERAL_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("Credit card number", re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b")),
    ("Email address", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
]

_PII_VAR_NAME_RE = re.compile(
    r"(?i)\b(ssn|social_security\w*|credit_card\w*|card_number|cvv|"
    r"dob|date_of_birth|passport\w*|driver.?s?_?licen[cs]e|"
    r"bank_account\w*|routing_number)\b"
)


class PiiInLogsCheck(Check):
    check_id = CHECK_ID

    def run(self, target: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in iter_text_files(target):
            text = read_text_safe(path)
            if text is None:
                continue
            rel = relative_asset_path(path, target)
            for lineno, line in enumerate(text.splitlines(), start=1):
                if not _LOG_CALL_RE.search(line):
                    continue

                for label, pattern in _PII_LITERAL_PATTERNS:
                    if pattern.search(line):
                        findings.append(
                            make_finding(
                                CHECK_ID,
                                affected_asset=str(rel),
                                evidence=f"Literal {label} found in a logging call.",
                                line=lineno,
                            )
                        )

                var_match = _PII_VAR_NAME_RE.search(line)
                if var_match:
                    findings.append(
                        make_finding(
                            CHECK_ID,
                            affected_asset=str(rel),
                            evidence=(
                                f"A PII-suggestive field (`{var_match.group(0)}`) is "
                                "interpolated into a logging call."
                            ),
                            line=lineno,
                        )
                    )
        return findings
