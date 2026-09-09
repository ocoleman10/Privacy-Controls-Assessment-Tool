import json
import os
import urllib.request

from scanner.engine import run_scan
from scanner.report import render_json, render_markdown

# 2 secrets + 1 env file + 2 PII-in-logs + 1 encryption + 2 unpinned deps = 8,
# the same on every platform. Vulnerable-dependency never fires by default
# (offline). Permissions is the one platform-dependent check: it's a no-op on
# native Windows (POSIX mode bits don't exist there), but on a real POSIX
# checkout (Linux CI, WSL, macOS) sample_target/.env is genuinely
# world-readable -- git only tracks the executable bit, not read/write bits,
# so a fresh clone always gets the umask-default mode regardless of what was
# committed. That's not a bug in the fixture: a committed .env file that's
# also world-readable really is one more real finding, not a false positive,
# so the expected count is +1 on POSIX rather than something to suppress.
EXPECTED_SAMPLE_TARGET_FINDINGS = 9 if os.name == "posix" else 8


def test_run_scan_produces_expected_shape(sample_target):
    findings = run_scan(sample_target)
    assert len(findings) == EXPECTED_SAMPLE_TARGET_FINDINGS

    # Sorted most-severe first.
    ranks = [f.severity.rank for f in findings]
    assert ranks == sorted(ranks)

    # Finding IDs are sequential and assigned only after sorting.
    ids = [f.finding_id for f in findings]
    assert ids == [f"PCAT-{i:04d}" for i in range(1, len(findings) + 1)]


def test_run_scan_against_a_single_file_target(sample_target):
    # Regression test: Path.rglob() (which every check uses internally)
    # silently yields nothing when target is a file rather than a
    # directory — pointing the CLI at sample_target/app.py used to produce
    # 0 findings instead of the 4 it actually contains.
    findings = run_scan(sample_target / "app.py")

    assert len(findings) == 4
    assert all(f.affected_asset == "app.py" for f in findings)


def test_run_scan_never_touches_the_network_by_default(sample_target, monkeypatch):
    def _boom(*args, **kwargs):
        raise AssertionError("run_scan must not hit the network unless online=True")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    run_scan(sample_target)  # should not raise


def test_render_markdown_includes_scope_statement_and_every_finding(sample_target):
    findings = run_scan(sample_target)
    output = render_markdown(findings, str(sample_target), "2026-01-01 00:00 UTC")

    assert "Scope statement" in output
    for finding in findings:
        assert finding.finding_id in output


def test_render_markdown_with_no_findings_renders_cleanly():
    output = render_markdown([], "some/target", "2026-01-01 00:00 UTC")
    assert "No findings identified" in output


def test_render_json_round_trips_finding_count(sample_target):
    findings = run_scan(sample_target)
    payload = json.loads(render_json(findings, str(sample_target), "2026-01-01 00:00 UTC"))

    assert payload["total_findings"] == len(findings)
    assert len(payload["findings"]) == len(findings)
    assert {f["finding_id"] for f in payload["findings"]} == {f.finding_id for f in findings}
