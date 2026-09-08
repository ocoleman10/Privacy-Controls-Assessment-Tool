"""Shared helpers for walking a target tree and reading files safely."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Iterator

IGNORED_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    "site-packages",
    "reports",
}

# Extensions worth scanning as text for secrets/PII/config patterns. Binary
# and generated files are skipped rather than read-and-ignored, since that's
# both faster and avoids garbage matches from decoded binary noise.
TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".cs",
    ".c", ".cpp", ".h", ".hpp", ".rs",
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".txt", ".sh", ".ps1",
}


def iter_files(target: Path) -> Iterator[Path]:
    """Yield every file under target, skipping noise directories.

    target may be a directory (the usual case) or a single file — pointing
    the scanner at one file you're curious about is a reasonable thing to
    want, and Path.rglob() silently yields nothing if target isn't a
    directory, so that case is handled explicitly here rather than by every
    check rediscovering the same surprise.
    """
    if target.is_file():
        yield target
        return
    for path in target.rglob("*"):
        if path.is_dir():
            continue
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        yield path


def iter_text_files(target: Path) -> Iterator[Path]:
    """Like iter_files, but restricted to extensions worth scanning as text.

    A dotfile like `.env` has suffix "" and name ".env" — TEXT_EXTENSIONS
    includes ".env" as a literal name check too, handled by the caller where
    needed; here we match on suffix, and treat files with no suffix but a
    name in TEXT_EXTENSIONS (e.g. ".env") as text too.
    """
    for path in iter_files(target):
        if path.suffix in TEXT_EXTENSIONS or path.name in TEXT_EXTENSIONS:
            yield path


def relative_asset_path(path: Path, target: Path) -> str:
    """Display path for a finding's affected_asset.

    When target is a directory, this is just path relative to it, as
    before. When target is itself the file being scanned, path == target,
    and path.relative_to(target) would collapse to "." — technically
    correct but reads as broken in a report, so show the filename instead.
    """
    if target.is_file():
        return path.name
    return str(path.relative_to(target))


def read_text_safe(path: Path) -> str | None:
    """Read a file as UTF-8, tolerating decode errors; None if unreadable."""
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return None


def is_git_ignored(path: Path) -> bool:
    """True if `git check-ignore` says this path is ignored.

    Returns False (not ignored) if git isn't available or the path isn't
    inside a git working tree — a conservative default so we don't silently
    suppress findings just because git couldn't be consulted.
    """
    try:
        result = subprocess.run(
            ["git", "check-ignore", "-q", str(path)],
            cwd=path.parent,
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return False


def is_git_tracked(path: Path, repo_root: Path) -> bool:
    """True if the path is tracked by git in the repo rooted at repo_root."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "--error-unmatch", str(path)],
            cwd=repo_root,
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return False
