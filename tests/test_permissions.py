import os

import pytest

import scanner.checks.permissions as permissions_module
from scanner.checks.permissions import PermissionsCheck

posix_only = pytest.mark.skipif(
    os.name != "posix", reason="POSIX permission bits don't exist on this platform"
)


@posix_only
def test_flags_world_readable_private_key(tmp_path):
    key_file = tmp_path / "id_rsa"
    key_file.write_text("fake-fixture-key-material")
    key_file.chmod(0o644)  # world-readable

    findings = PermissionsCheck().run(tmp_path)
    assert len(findings) == 1
    assert findings[0].affected_asset == "id_rsa"


@posix_only
def test_does_not_flag_properly_restricted_key(tmp_path):
    key_file = tmp_path / "id_rsa"
    key_file.write_text("fake-fixture-key-material")
    key_file.chmod(0o600)  # owner-only

    findings = PermissionsCheck().run(tmp_path)
    assert findings == []


def test_is_a_documented_noop_on_non_posix(tmp_path, monkeypatch):
    # Exercised regardless of the platform tests actually run on, by forcing
    # the module's os.name check down the non-POSIX branch.
    monkeypatch.setattr(permissions_module.os, "name", "nt")
    key_file = tmp_path / "id_rsa"
    key_file.write_text("fake-fixture-key-material")

    assert PermissionsCheck().run(tmp_path) == []
