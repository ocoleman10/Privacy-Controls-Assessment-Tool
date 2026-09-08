"""Committed .env files.

Severity depends on how exposed the file actually is: a .env file that git
already tracks (i.e. it would be in the pushed history of a shared repo) is
Critical — the leak has already happened as far as anyone with repo access
is concerned. A .env file that's merely present on disk and not gitignored
is still a policy gap (High, the catalog default) since it's one `git add .`
away from the same outcome, but it isn't in history yet.
"""

from __future__ import annotations

from pathlib import Path

from scanner.checks.base import Check, make_finding
from scanner.finding import Finding, Severity
from scanner.util import iter_files, is_git_ignored, is_git_tracked, relative_asset_path

CHECK_ID = "PCAT-ENV"


class EnvFileCheck(Check):
    check_id = CHECK_ID

    def run(self, target: Path) -> list[Finding]:
        findings: list[Finding] = []
        # is_git_tracked shells out with this as its cwd, which must be a
        # directory — when target is itself the file being scanned, walk up
        # to its parent so git still has a working tree to run in.
        repo_root = target if target.is_dir() else target.parent

        for path in iter_files(target):
            if not (path.name == ".env" or path.name.startswith(".env.")):
                continue
            if path.name == ".env.example" or path.name == ".env.sample":
                continue  # template files are the recommended pattern, not a finding
            if is_git_ignored(path):
                continue

            rel = relative_asset_path(path, target)
            tracked = is_git_tracked(path, repo_root)
            finding = make_finding(
                CHECK_ID,
                affected_asset=str(rel),
                evidence=(
                    "File is tracked by git (present in repo history, "
                    "exposed to anyone with repo access)."
                    if tracked
                    else "File is present on disk, untracked, and not covered by .gitignore."
                ),
            )
            if tracked:
                finding.severity = Severity.CRITICAL
            findings.append(finding)
        return findings
