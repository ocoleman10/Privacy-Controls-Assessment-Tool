"""Hardcoded secrets and API keys.

Two tiers of pattern: high-confidence provider-specific formats (AWS keys,
GitHub/Slack tokens, PEM private key blocks), and a generic
name-looks-like-a-credential heuristic for anything assigned a literal
string. The generic tier is the noisier one, so it's filtered against an
obvious-placeholder list and against lines that are clearly pulling the
value from the environment rather than hardcoding it.
"""

from __future__ import annotations

import re
from pathlib import Path

from scanner.checks.base import Check, make_finding
from scanner.finding import Finding
from scanner.util import iter_text_files, read_text_safe

CHECK_ID = "PCAT-SECRET"

_PROVIDER_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Private key block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")),
]

_GENERIC_CREDENTIAL_RE = re.compile(
    r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b"
    r"\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]"
)

_PLACEHOLDER_RE = re.compile(
    r"(?i)^(changeme|change_me|xxx+|todo|example|placeholder|your[_-]?\w+[_-]?here|"
    r"<.*>|\$\{.*\}|none|null)$"
)

_ENV_LOOKUP_HINTS = ("os.environ", "os.getenv", "process.env", "ENV[", "getenv(")


class HardcodedSecretsCheck(Check):
    check_id = CHECK_ID

    def run(self, target: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in iter_text_files(target):
            text = read_text_safe(path)
            if text is None:
                continue
            rel = path.relative_to(target)
            for lineno, line in enumerate(text.splitlines(), start=1):
                if any(hint in line for hint in _ENV_LOOKUP_HINTS):
                    continue

                for label, pattern in _PROVIDER_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        findings.append(
                            make_finding(
                                CHECK_ID,
                                affected_asset=str(rel),
                                evidence=f"{label} pattern matched: {_redact(match.group(0))}",
                                line=lineno,
                            )
                        )

                generic = _GENERIC_CREDENTIAL_RE.search(line)
                if generic:
                    value = generic.group(2)
                    if not _PLACEHOLDER_RE.match(value):
                        findings.append(
                            make_finding(
                                CHECK_ID,
                                affected_asset=str(rel),
                                evidence=f"Literal value assigned to a credential-shaped name: {_redact(value)}",
                                line=lineno,
                            )
                        )
        return findings


def _redact(value: str) -> str:
    """Show enough of a matched secret to confirm the finding without
    reproducing the full credential in the report."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"
