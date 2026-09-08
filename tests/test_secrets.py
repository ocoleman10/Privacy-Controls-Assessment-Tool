from scanner.checks.secrets import HardcodedSecretsCheck


def test_flags_hardcoded_secrets_in_app_py(sample_target):
    findings = HardcodedSecretsCheck().run(sample_target)

    # Exactly two lines in the fixture are meant to trigger this check: the
    # fake AWS key and the fake db_password literal. A third line pulls its
    # value from os.environ and must never appear here.
    assert len(findings) == 2
    assert all(f.affected_asset == "app.py" for f in findings)

    evidence = " ".join(f.evidence for f in findings)
    assert "AWS Access Key ID" in evidence
    assert "credential-shaped name" in evidence


def test_does_not_flag_placeholder_or_env_sourced_values(sample_target, tmp_path):
    fixture = tmp_path / "config.py"
    fixture.write_text(
        "\n".join(
            [
                "password = 'changeme'",
                "api_key = os.environ['API_KEY']",
                "secret = \"\"",
            ]
        )
    )

    findings = HardcodedSecretsCheck().run(tmp_path)
    assert findings == []
