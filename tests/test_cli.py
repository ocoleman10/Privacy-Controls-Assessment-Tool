from cli import main


def test_no_fail_on_always_exits_zero(sample_target, capsys):
    # sample_target has 8 findings (3 critical, 3 high, 2 medium) but the
    # default behavior (no --fail-on) must stay report-only, exit 0 either way.
    assert main([str(sample_target)]) == 0


def test_fail_on_critical_exits_nonzero_when_a_critical_finding_exists(sample_target, capsys):
    # sample_target has critical findings (hardcoded secrets + the committed
    # .env file, which env_files.py escalates to critical).
    assert main([str(sample_target), "--fail-on", "critical"]) == 1


def test_fail_on_low_exits_nonzero_on_any_finding(sample_target, capsys):
    # "low" is the least severe threshold, so any finding at all should trip it.
    assert main([str(sample_target), "--fail-on", "low"]) == 1


def test_fail_on_exits_zero_when_nothing_meets_the_threshold(tmp_path, capsys):
    # An empty target has zero findings, so no threshold should ever trip.
    assert main([str(tmp_path), "--fail-on", "critical"]) == 0
    assert main([str(tmp_path), "--fail-on", "low"]) == 0


def test_fail_on_writes_report_before_evaluating_exit_code(sample_target, tmp_path, capsys):
    # The report should still be produced even on a failing run -- --fail-on
    # gates the exit code, not whether you get to see what was found.
    report_path = tmp_path / "report.md"
    exit_code = main([str(sample_target), "--fail-on", "critical", "-o", str(report_path)])

    assert exit_code == 1
    assert report_path.exists()
    assert "PCAT-0001" in report_path.read_text(encoding="utf-8")
