"""
Turns raw Bandit and Semgrep output into:
  - report.md      a readable comment for the pull request
  - findings.json  one clean list of findings (the AI step will read this later)

Usage:
    python reviewer/build_report.py bandit.json semgrep.json report.md findings.json
"""

import json
import sys

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
SEMGREP_SEVERITY = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


def load_json(path):
    """Return the parsed file, or None if the scanner produced nothing usable."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def bandit_findings(data):
    findings = []
    for r in data.get("results", []):
        findings.append({
            "tool": "bandit",
            "rule": f"{r.get('test_id', '')} {r.get('test_name', '')}".strip(),
            "severity": r.get("issue_severity", "LOW").upper(),
            "file": r.get("filename", ""),
            "line": r.get("line_number", 0),
            "message": r.get("issue_text", ""),
            "code": r.get("code", ""),
        })
    return findings


def semgrep_findings(data):
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        findings.append({
            "tool": "semgrep",
            "rule": r.get("check_id", "").split(".")[-1],
            "severity": SEMGREP_SEVERITY.get(extra.get("severity", "INFO").upper(), "LOW"),
            "file": r.get("path", ""),
            "line": r.get("start", {}).get("line", 0),
            "message": extra.get("message", ""),
            "code": extra.get("lines", ""),
        })
    return findings


def clean(text, limit=140):
    """Make text safe for one markdown table cell."""
    text = " ".join(str(text).split()).replace("|", "\\|")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def build_markdown(findings, problems):
    lines = ["## Security review", ""]

    for p in problems:
        lines.append(f"> **Warning:** {p}")
    if problems:
        lines.append("")

    if not findings:
        lines.append("No issues found in `app/`.")
        return "\n".join(lines) + "\n"

    counts = {s: sum(f["severity"] == s for f in findings) for s in SEVERITY_ORDER}
    lines.append(f"Found **{len(findings)}** possible issues: "
                 f"{counts['HIGH']} high, {counts['MEDIUM']} medium, {counts['LOW']} low.")
    lines.append("")
    lines.append("| Severity | Tool | Rule | Location | Issue |")
    lines.append("|---|---|---|---|---|")
    for f in findings:
        lines.append(f"| {f['severity']} | {f['tool']} | {clean(f['rule'], 50)} | "
                     f"`{f['file']}:{f['line']}` | {clean(f['message'])} |")
    lines.append("")
    lines.append("_These are raw scanner results. Some may be false alarms._")
    return "\n".join(lines) + "\n"


def main():
    if len(sys.argv) != 5:
        print(__doc__)
        raise SystemExit(1)
    bandit_path, semgrep_path, report_path, findings_path = sys.argv[1:]

    findings, problems = [], []

    bandit = load_json(bandit_path)
    if bandit is None:
        problems.append("Bandit produced no results file, so its checks are missing from this report.")
    else:
        findings += bandit_findings(bandit)

    semgrep = load_json(semgrep_path)
    if semgrep is None:
        problems.append("Semgrep produced no results file, so its checks are missing from this report.")
    else:
        findings += semgrep_findings(semgrep)
        if semgrep.get("errors"):
            problems.append(f"Semgrep reported {len(semgrep['errors'])} error(s). See the scan-results artifact.")

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 3), f["file"], f["line"]))

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(build_markdown(findings, problems))
    with open(findings_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    print(f"{len(findings)} findings written to {report_path} and {findings_path}")


if __name__ == "__main__":
    main()
