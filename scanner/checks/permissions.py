"""Overly broad permissions on sensitive files.

Uses POSIX mode bits (world-readable/writable) on files whose name suggests
they hold something sensitive: private keys, certs, credential/secrets
files, .env files.

Known limitation, stated here and in the README: POSIX mode bits don't exist
on native Windows — NTFS uses ACLs instead, which `Path.stat().st_mode`
doesn't meaningfully reflect. On Windows this check is a documented no-op
rather than a false "everything's fine": run the scan from WSL (or any POSIX
environment) against the same files for a real answer. A Windows-native ACL
check (via icacls or pywin32) is a reasonable future enhancement, not
attempted here.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from scanner.checks.base import Check, make_finding
from scanner.finding import Finding
from scanner.util import iter_files, relative_asset_path

CHECK_ID = "PCAT-PERM"

_SENSITIVE_NAME_RE = re.compile(
    r"(?i)(^id_rsa$|^id_ed25519$|^id_dsa$|\.pem$|\.key$|\.pfx$|\.p12$|"
    r"credentials|secrets?\.(ya?ml|json)$|^\.env$|^\.env\.)"
)


class PermissionsCheck(Check):
    check_id = CHECK_ID

    def run(self, target: Path) -> list[Finding]:
        if os.name != "posix":
            return []

        findings: list[Finding] = []
        for path in iter_files(target):
            if not _SENSITIVE_NAME_RE.search(path.name):
                continue
            try:
                mode = path.stat().st_mode
            except OSError:
                continue

            world_readable = bool(mode & stat.S_IROTH)
            world_writable = bool(mode & stat.S_IWOTH)
            if not (world_readable or world_writable):
                continue

            rel = relative_asset_path(path, target)
            perms = stat.filemode(mode)
            kind = "world-writable" if world_writable else "world-readable"
            findings.append(
                make_finding(
                    CHECK_ID,
                    affected_asset=str(rel),
                    evidence=f"Sensitive file is {kind} (mode {perms}).",
                )
            )
        return findings
