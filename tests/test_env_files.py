import subprocess

from scanner.checks.env_files import EnvFileCheck
from scanner.finding import Severity


def test_flags_committed_env_file_as_critical(sample_target):
    findings = EnvFileCheck().run(sample_target)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.affected_asset == ".env"
    # sample_target/.env is committed to this repo's own history, so the
    # check should treat it as an already-realized leak (Critical), not a
    # mere policy gap (the catalog default, High).
    assert finding.severity == Severity.CRITICAL


def test_does_not_flag_env_example_template(sample_target):
    findings = EnvFileCheck().run(sample_target)
    assert all(f.affected_asset != ".env.example" for f in findings)


def test_does_not_flag_gitignored_env_file(tmp_path):
    # `git check-ignore` needs an actual working tree to consult .gitignore
    # against — outside a repo it fails closed (not ignored) per util.py's
    # documented conservative default, so this test needs a real repo.
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / ".gitignore").write_text(".env\n")
    (tmp_path / ".env").write_text("API_KEY=fixture\n")

    findings = EnvFileCheck().run(tmp_path)
    assert findings == []
