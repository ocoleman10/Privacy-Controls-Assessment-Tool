"""Control catalog: the mapping from each check to a named control.

This is the part that makes this a privacy-and-controls project rather than
a linter. Every check below cites the specific NIST CSF 2.0 subcategory or
CIS Controls v8 safeguard it evidences a gap against.

Provenance and a caveat, stated plainly: the reference IDs and titles quoted
here were verified against public NIST CSF 2.0 and CIS Controls v8
documentation as of 2026-09-07 (NIST CSWP 29 / csf.tools for CSF 2.0;
CIS Controls Navigator v8 / bastion.tech for CIS v8). Both frameworks are
revised periodically. Before using this catalog in a client-facing or
interview context, re-check each reference against the live NIST CSF 2.0
Reference Tool (nist.gov) and the CIS Controls Navigator (cisecurity.org)
rather than trusting this file as the source of truth going forward.

Sources consulted:
- NIST CSF 2.0 Core, NIST CSWP 29 (nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf)
- csf.tools reference pages for PR.AA, PR.DS, ID.AM, ID.RA, GV.SC (v2.0)
- CIS Controls v8 safeguard list, cisecurity.org Controls Navigator v8
"""

from __future__ import annotations

from dataclasses import dataclass

from scanner.finding import ControlRef, Severity


@dataclass(frozen=True)
class CheckMeta:
    check_id: str
    title: str
    default_severity: Severity
    control_refs: list[ControlRef]
    remediation: str
    estimated_effort: str


CATALOG: dict[str, CheckMeta] = {
    "PCAT-SECRET": CheckMeta(
        check_id="PCAT-SECRET",
        title="Hardcoded secret or API key in source",
        default_severity=Severity.CRITICAL,
        control_refs=[
            ControlRef(
                "NIST CSF 2.0",
                "PR.AA-05",
                "Access permissions, entitlements, and authorizations are "
                "defined in a policy, managed, enforced, and reviewed, and "
                "incorporate the principles of least privilege and "
                "separation of duties",
            ),
            ControlRef(
                "CIS Controls v8",
                "16.12",
                "Implement Code-Level Security Checks",
            ),
        ],
        remediation=(
            "Remove the credential from source control and rotate it "
            "immediately (treat it as compromised the moment it was "
            "committed, regardless of repo visibility). Load it at runtime "
            "from a secrets manager or an environment variable that is "
            "itself excluded from version control, and add a pre-commit "
            "secret-scanning hook to prevent recurrence."
        ),
        estimated_effort="Low (rotate same-day; refactor call sites within one sprint)",
    ),
    "PCAT-ENV": CheckMeta(
        check_id="PCAT-ENV",
        title="Committed .env file with secrets exposure risk",
        default_severity=Severity.HIGH,
        control_refs=[
            ControlRef(
                "NIST CSF 2.0",
                "PR.DS-01",
                "The confidentiality, integrity, and availability of "
                "data-at-rest are protected",
            ),
            ControlRef(
                "CIS Controls v8",
                "3.3",
                "Configure Data Access Control Lists",
            ),
        ],
        remediation=(
            "Remove the file from version control history (not just the "
            "working tree — a plain `git rm` still leaves it in history), "
            "add the pattern to .gitignore, rotate every credential the file "
            "contained, and distribute a `.env.example` with placeholder "
            "keys instead."
        ),
        estimated_effort="Low (same-day removal and rotation)",
    ),
    "PCAT-PII-LOG": CheckMeta(
        check_id="PCAT-PII-LOG",
        title="Personally identifiable information written to logs",
        default_severity=Severity.HIGH,
        control_refs=[
            ControlRef(
                "NIST CSF 2.0",
                "PR.DS-01",
                "The confidentiality, integrity, and availability of "
                "data-at-rest are protected",
            ),
            ControlRef(
                "CIS Controls v8",
                "3.11",
                "Encrypt Sensitive Data at Rest",
            ),
        ],
        remediation=(
            "Remove PII fields from log statements or mask/redact them "
            "before the log call (e.g. last-4 of an account number instead "
            "of the full value). Where the full value is genuinely needed "
            "for support workflows, route it to a separate, access-controlled "
            "and encrypted store rather than general application logs."
        ),
        estimated_effort="Medium (requires touching each call site and a log-retention review)",
    ),
    "PCAT-DEP-UNPINNED": CheckMeta(
        check_id="PCAT-DEP-UNPINNED",
        title="Unpinned dependency version",
        default_severity=Severity.MEDIUM,
        control_refs=[
            ControlRef(
                "NIST CSF 2.0",
                "ID.AM-02",
                "Inventories of software, services, and systems managed by "
                "the organization are maintained",
            ),
            ControlRef(
                "CIS Controls v8",
                "16.1",
                "Establish and Maintain a Secure Application Development Process",
            ),
        ],
        remediation=(
            "Pin the dependency to an exact, tested version (or a lockfile) "
            "so the set of code actually running is known and reproducible. "
            "Unpinned ranges mean the software inventory can change without "
            "a corresponding review."
        ),
        estimated_effort="Low (pin versions, regenerate lockfile, re-test)",
    ),
    "PCAT-DEP-VULN": CheckMeta(
        check_id="PCAT-DEP-VULN",
        title="Dependency with a known public advisory",
        default_severity=Severity.HIGH,
        control_refs=[
            ControlRef(
                "NIST CSF 2.0",
                "ID.RA-01",
                "Vulnerabilities in first-party and third-party assets are "
                "identified, validated, and recorded",
            ),
            ControlRef(
                "CIS Controls v8",
                "7.2",
                "Establish and Maintain a Remediation Process",
            ),
        ],
        remediation=(
            "Upgrade to a patched version per the advisory. If no patched "
            "version exists yet, document a compensating control and a "
            "re-check date rather than leaving the finding open silently."
        ),
        estimated_effort="Low to Medium (depends on breaking changes in the patched version)",
    ),
    "PCAT-PERM": CheckMeta(
        check_id="PCAT-PERM",
        title="Sensitive file with overly broad (world-readable/writable) permissions",
        default_severity=Severity.HIGH,
        control_refs=[
            ControlRef(
                "NIST CSF 2.0",
                "PR.AA-05",
                "Access permissions, entitlements, and authorizations are "
                "defined in a policy, managed, enforced, and reviewed, and "
                "incorporate the principles of least privilege and "
                "separation of duties",
            ),
            ControlRef(
                "CIS Controls v8",
                "3.3",
                "Configure Data Access Control Lists",
            ),
        ],
        remediation=(
            "Restrict the file to the owning user/service account only "
            "(e.g. `chmod 600` for private keys and credential files). "
            "Audit how the file ended up world-readable — a common cause is "
            "an overly permissive umask on the host, which should be fixed "
            "at the host level, not just per-file."
        ),
        estimated_effort="Low (chmod fix); Medium if a host-level umask policy is the root cause",
    ),
    "PCAT-ENCRYPT": CheckMeta(
        check_id="PCAT-ENCRYPT",
        title="Missing or disabled encryption control (at rest or in transit)",
        default_severity=Severity.HIGH,
        control_refs=[
            ControlRef(
                "NIST CSF 2.0",
                "PR.DS-01",
                "The confidentiality, integrity, and availability of "
                "data-at-rest are protected",
            ),
            ControlRef(
                "NIST CSF 2.0",
                "PR.DS-02",
                "The confidentiality, integrity, and availability of "
                "data-in-transit are protected",
            ),
            ControlRef(
                "CIS Controls v8",
                "3.11",
                "Encrypt Sensitive Data at Rest",
            ),
        ],
        remediation=(
            "Re-enable TLS/SSL on the connection (remove the explicit "
            "disabled-SSL-mode setting or equivalent flag) and confirm the "
            "underlying data store has encryption at rest enabled. Treat a "
            "disabled encryption flag in config as a deliberate finding, not "
            "a default to leave in place for local development without a "
            "matching override for production."
        ),
        estimated_effort="Low (flip a config flag) to Medium (if the data store lacks at-rest encryption entirely)",
    ),
}
