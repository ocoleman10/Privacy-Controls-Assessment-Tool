"""Renders a scan's findings as a consulting-style deliverable.

Two formats: Markdown (the human-facing report, meant to be read, not just
grepped) and JSON (machine-readable, for feeding into something else later).
Both carry the scope statement up front — see README.md's "Scope discipline"
section for why that's non-negotiable rather than a nice-to-have.
"""

from __future__ import annotations

import json

from scanner.finding import Finding, Severity

SCOPE_STATEMENT = (
    "This assessment covers only systems the assessor owns and controls: the "
    "repository, source tree, or configuration under scan at the target path "
    "given on the command line. No third-party, employer, or academic "
    "infrastructure was scanned as part of this report."
)


def render_markdown(findings: list[Finding], target: str, generated_at: str) -> str:
    lines: list[str] = []
    lines.append("# Privacy and Controls Assessment — Findings Report")
    lines.append("")
    lines.append(f"**Scope target:** `{target}`  ")
    lines.append(f"**Generated:** {generated_at}  ")
    lines.append(f"**Total findings:** {len(findings)}")
    lines.append("")
    lines.append("## Scope statement")
    lines.append("")
    lines.append(SCOPE_STATEMENT)
    lines.append("")
    lines.append("## Summary by severity")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for severity in Severity:
        count = sum(1 for f in findings if f.severity == severity)
        lines.append(f"| {severity.value} | {count} |")
    lines.append("")
    lines.append("## Findings")
    lines.append("")

    if not findings:
        lines.append("No findings identified in this scan.")
    for finding in findings:
        lines.append(f"### {finding.finding_id} — {finding.title} ({finding.severity.value})")
        lines.append("")
        lines.append(f"- **Check:** `{finding.check_id}`")
        asset = finding.affected_asset + (f":{finding.line}" if finding.line else "")
        lines.append(f"- **Affected asset:** `{asset}`")
        refs = "; ".join(str(ref) for ref in finding.control_refs)
        lines.append(f"- **Control reference(s):** {refs}")
        lines.append(f"- **Evidence:** {finding.evidence}")
        lines.append(f"- **Remediation:** {finding.remediation}")
        lines.append(f"- **Estimated remediation effort:** {finding.estimated_effort}")
        lines.append("")

    return "\n".join(lines)


def render_json(findings: list[Finding], target: str, generated_at: str) -> str:
    payload = {
        "scope_target": target,
        "generated_at": generated_at,
        "scope_statement": SCOPE_STATEMENT,
        "total_findings": len(findings),
        "findings": [
            {
                "finding_id": f.finding_id,
                "check_id": f.check_id,
                "title": f.title,
                "severity": f.severity.value,
                "affected_asset": f.affected_asset,
                "line": f.line,
                "control_refs": [
                    {"framework": r.framework, "ref_id": r.ref_id, "title": r.title}
                    for r in f.control_refs
                ],
                "evidence": f.evidence,
                "remediation": f.remediation,
                "estimated_effort": f.estimated_effort,
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2)
