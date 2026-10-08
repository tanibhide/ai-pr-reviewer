"""
AI triage of scanner findings.

Reads the raw findings a scanner run produced (findings.json), shows each one
to a local LLM together with the code around it, and asks the model to decide:
  - is this a real issue or a false alarm?
  - is it a duplicate of another finding?
  - what is the one-line fix?

Writes:
  triage.json      the model's verdict for every finding
  triage_report.md a readable summary

Usage:
    python triage.py findings.json app triage.json triage_report.md
    python triage.py findings.json app triage.json triage_report.md --model qwen2.5:3b

The scanners run in CI; this step runs on your machine, where Ollama is.
"""

import argparse
import json
import re
import sys

import ollama

SYSTEM_PROMPT = (
    "You are a security engineer triaging the output of automated code scanners. "
    "Scanners are noisy: they report duplicates and false alarms. "
    "For each finding you are given the scanner's message and the relevant code. "
    "Decide whether it is a REAL issue or a FALSE_ALARM, and give a one-sentence reason "
    "and a one-sentence fix. Judge only from the code shown. "
    "Reply with a single JSON object and nothing else: "
    '{"verdict": "REAL" or "FALSE_ALARM", "reason": "...", "fix": "..."}'
)


def read_code(root, path, line, context=4):
    """Return a few lines of code around the finding, with line numbers."""
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        # The finding's path is relative to the repo root; try under `root` too.
        try:
            name = path.split("/", 1)[-1]
            with open(f"{root}/{name}", encoding="utf-8") as f:
                lines = f.readlines()
        except OSError:
            return "(source not found)"
    if not line:
        return "".join(lines[:context]).rstrip()
    lo = max(0, line - context - 1)
    hi = min(len(lines), line + context)
    out = []
    for i in range(lo, hi):
        marker = ">>" if i == line - 1 else "  "
        out.append(f"{marker} {i + 1}: {lines[i].rstrip()}")
    return "\n".join(out)


def extract_json(text):
    """Pull the first JSON object out of the model's reply."""
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


def triage_one(model, finding, code):
    user = (
        f"Scanner: {finding['tool']}\n"
        f"Rule: {finding['rule']}\n"
        f"Reported severity: {finding['severity']}\n"
        f"Message: {finding['message']}\n"
        f"File: {finding['file']} line {finding['line']}\n\n"
        f"Code:\n{code}\n"
    )
    try:
        resp = ollama.chat(
            model=model,
            messages=[{"role": "system", "content": SYSTEM_PROMPT},
                      {"role": "user", "content": user}],
            options={"temperature": 0},
        )
        reply = resp["message"]["content"]
    except Exception as e:
        return {"verdict": "ERROR", "reason": f"model call failed: {e}", "fix": ""}

    parsed = extract_json(reply)
    if not parsed or "verdict" not in parsed:
        return {"verdict": "UNPARSED", "reason": reply[:200], "fix": ""}
    parsed["verdict"] = str(parsed.get("verdict", "")).upper()
    parsed.setdefault("reason", "")
    parsed.setdefault("fix", "")
    return parsed


def dedupe(findings):
    """Mark findings that repeat an earlier one at the same file and line."""
    seen = {}
    for f in findings:
        key = (f["file"], f["line"])
        f["duplicate_of"] = seen.get(key)
        if key not in seen:
            seen[key] = f"{f['tool']}:{f['rule']}"
    return findings


def clean(text, limit=160):
    text = " ".join(str(text).split()).replace("|", "\\|")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def build_report(results):
    real = [r for r in results if r["triage"]["verdict"] == "REAL" and not r["duplicate_of"]]
    false = [r for r in results if r["triage"]["verdict"] == "FALSE_ALARM"]
    dup = [r for r in results if r["duplicate_of"]]
    other = [r for r in results if r["triage"]["verdict"] in ("ERROR", "UNPARSED")]

    lines = ["## Security review (AI triage)", ""]
    lines.append(f"The scanners reported **{len(results)}** findings. After triage: "
                 f"**{len(real)} to fix**, {len(false)} likely false alarms, "
                 f"{len(dup)} duplicates.")
    if other:
        lines.append(f"\n> **Note:** {len(other)} finding(s) could not be triaged automatically.")
    lines.append("")

    if real:
        lines.append("### Issues to fix")
        lines.append("| Severity | Location | Issue | Suggested fix |")
        lines.append("|---|---|---|---|")
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        for r in sorted(real, key=lambda r: order.get(r["severity"], 3)):
            lines.append(f"| {r['severity']} | `{r['file']}:{r['line']}` | "
                         f"{clean(r['triage']['reason'])} | {clean(r['triage']['fix'])} |")
        lines.append("")

    if false:
        lines.append("### Dismissed as false alarms")
        for r in false:
            lines.append(f"- `{r['file']}:{r['line']}` ({r['rule']}) — {clean(r['triage']['reason'])}")
        lines.append("")

    lines.append("_Triage by a local LLM. Treat as a first pass, not the final word._")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("findings")
    parser.add_argument("source_root")
    parser.add_argument("out_json")
    parser.add_argument("out_report")
    parser.add_argument("--model", default="llama3.2:3b")
    args = parser.parse_args()

    with open(args.findings, encoding="utf-8") as f:
        findings = json.load(f)

    if not findings:
        with open(args.out_report, "w", encoding="utf-8") as f:
            f.write("## Security review (AI triage)\n\nNo findings to triage.\n")
        with open(args.out_json, "w", encoding="utf-8") as f:
            json.dump([], f)
        print("No findings to triage.")
        return

    findings = dedupe(findings)
    results = []
    for i, finding in enumerate(findings, 1):
        if finding["duplicate_of"]:
            verdict = {"verdict": "DUPLICATE",
                       "reason": f"same line already flagged by {finding['duplicate_of']}", "fix": ""}
        else:
            code = read_code(args.source_root, finding["file"], finding["line"])
            verdict = triage_one(args.model, finding, code)
        print(f"[{i}/{len(findings)}] {finding['file']}:{finding['line']} "
              f"{finding['rule']} -> {verdict['verdict']}")
        results.append({**finding, "triage": verdict})

    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    with open(args.out_report, "w", encoding="utf-8") as f:
        f.write(build_report(results))

    print(f"\nWrote {args.out_json} and {args.out_report}")


if __name__ == "__main__":
    main()
