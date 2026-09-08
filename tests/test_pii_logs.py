from scanner.checks.pii_logs import PiiInLogsCheck


def test_flags_pii_suggestive_variable_and_literal_email(sample_target):
    findings = PiiInLogsCheck().run(sample_target)

    assert len(findings) == 2
    assert all(f.affected_asset == "app.py" for f in findings)

    evidence = " ".join(f.evidence for f in findings)
    assert "ssn" in evidence
    assert "Email address" in evidence


def test_ignores_pii_shaped_values_outside_a_log_call(tmp_path):
    fixture = tmp_path / "app.py"
    fixture.write_text('ssn = "123-45-6789"\ncontact = "someone@example.com"\n')

    findings = PiiInLogsCheck().run(tmp_path)
    assert findings == []
