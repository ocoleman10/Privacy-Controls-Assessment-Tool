# Privacy and Controls Assessment Tool (PCAT)

A scanner that reviews a codebase for privacy and security hygiene problems,
maps each finding to a named control (NIST CSF 2.0 / CIS Controls v8), and
produces a consulting-style findings report — finding ID, severity, affected
asset, control reference, evidence, remediation, and estimated remediation
effort.

This is advisory tooling, not offensive security. It doesn't exploit
anything or probe a running system from the outside; it reads source and
config and tells you what a controls assessor would flag and why.

## Scope discipline

**Only ever run this against systems you own**: your own repositories, your
own machine, your own sandbox/Codespace. Do not point it at an employer's
infrastructure, a former employer's, a school's, or any third party's
systems without their explicit authorization. Every generated report states
this limitation up front (see `SCOPE_STATEMENT` in `scanner/report.py`)

## Install

```
py -m pip install -r requirements.txt
```

The scanner itself has **zero third-party runtime dependencies** — `requirements.txt` only pulls in `pytest`, for the test suite.

(`py` is the Windows launcher; use `python3` on macOS/Linux/WSL if `py` isn't
on your PATH.)

## Usage

```
py cli.py <target-path> [-o report.md] [--format md|json] [--online]
```

- `<target-path>` — the directory to scan.
- `-o/--output` — write the report to a file instead of stdout.
- `--format` — `md` (default, the human-facing report) or `json`
  (machine-readable).
- `--online` — also query [osv.dev](https://osv.dev) for known public
  advisories against exactly-pinned dependency versions. Off by default, so
  a plain scan never depends on network access.

Try it against the fixture that ships with this repo:

```
py cli.py sample_target
```

## What it checks

| Check | What it flags | Default severity |
| --- | --- | --- |
| `PCAT-SECRET` | Hardcoded secrets/API keys (provider-specific patterns plus a generic credential-shaped-name heuristic) | Critical |
| `PCAT-ENV` | Committed `.env` files (Critical if tracked by git — an already-realized leak; High if merely present and ungitignored) | High/Critical |
| `PCAT-PII-LOG` | PII (literal or field-name-suggestive) written to log/print calls | High |
| `PCAT-DEP-UNPINNED` | Dependencies not pinned to an exact version | Medium |
| `PCAT-DEP-VULN` | Pinned dependencies with a known public advisory (opt-in, `--online`) | High |
| `PCAT-PERM` | World-readable/writable sensitive files — private keys, `.pem`/`.pfx`/`.p12`, credentials/secrets files | High |
| `PCAT-ENCRYPT` | Disabled TLS/SSL or encryption flags (`sslmode=disable`, `ssl=false`, plaintext `http://` to a data/auth endpoint) | High |

`PCAT-PERM` is a documented no-op on native Windows — POSIX permission bits
don't exist there (NTFS uses ACLs instead). Run the scan from WSL for a real
answer on that one check; everything else works the same on both.

## The control mapping

Every check cites a specific NIST CSF 2.0 subcategory and/or CIS Controls
v8 safeguard in `controls/catalog.py` — that mapping is what makes this a
controls-assessment tool rather than a linter. The reference IDs and titles
were verified against public NIST/CIS documentation (not recalled from
memory) as of 2026-09-07; both frameworks are revised periodically, so
re-check each reference against the live NIST CSF 2.0 Reference Tool and the
CIS Controls Navigator before using this catalog in a client-facing context.
See the module docstring in `controls/catalog.py` for the exact sources
consulted.

## Project layout

```
cli.py                     entrypoint
scanner/
  finding.py                Finding/Severity/ControlRef data model
  util.py                   file-walking + git helpers shared by all checks
  engine.py                 runs every check, sorts, assigns finding IDs
  report.py                 Markdown/JSON report rendering
  checks/
    base.py                 Check ABC + make_finding() (pulls from the catalog)
    secrets.py, env_files.py, pii_logs.py, dependencies.py,
    permissions.py, encryption.py
controls/
  catalog.py                the control mapping — severity, control refs,
                             remediation text, effort estimate per check
sample_target/              synthetic fixture with one intentional issue
                             per check, plus negative cases — see its README
tests/                      pytest suite: one file per check + engine/report
                             integration tests
```

## Testing

```
py -m pytest
```

19 tests pass on native Windows; 2 more (real POSIX permission-bit checks)
run under WSL — see `tests/test_permissions.py`.
