from scanner.checks.encryption import EncryptionAtRestCheck


def test_flags_disabled_sslmode(sample_target):
    findings = EncryptionAtRestCheck().run(sample_target)

    assert len(findings) == 1
    assert findings[0].affected_asset == "db_config.py"
    assert "sslmode=disable" in findings[0].evidence


def test_does_not_flag_properly_configured_connection(tmp_path):
    fixture = tmp_path / "db_config.py"
    fixture.write_text('DATABASE_URL = "postgresql://user:pw@db:5432/app?sslmode=require"\n')

    findings = EncryptionAtRestCheck().run(tmp_path)
    assert findings == []
