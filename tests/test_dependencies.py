import urllib.request

from scanner.checks.dependencies import UnpinnedDependencyCheck, VulnerableDependencyCheck


def test_flags_unpinned_but_not_pinned_dependency(sample_target):
    findings = UnpinnedDependencyCheck().run(sample_target)

    assert len(findings) == 2
    evidence = {f.evidence for f in findings}
    assert any("requests" in e for e in evidence)
    assert any("flask>=2.0" in e for e in evidence)
    assert not any("pinned-package" in e for e in evidence)


def test_vulnerable_dependency_check_is_offline_by_default(sample_target):
    # offline=True is the default precisely so a plain scan never depends on
    # network access — verify the default, not just an explicit offline=True.
    findings = VulnerableDependencyCheck().run(sample_target)
    assert findings == []


def test_vulnerable_dependency_check_degrades_quietly_on_network_failure(sample_target, monkeypatch):
    def _boom(*args, **kwargs):
        raise OSError("no network available in test")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)

    findings = VulnerableDependencyCheck(offline=False).run(sample_target)
    assert findings == []
