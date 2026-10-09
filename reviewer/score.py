"""
Score one or more triage runs against a ground-truth file.

Ground truth lists, per file, the line numbers that contain a REAL vulnerability.
A finding on one of those lines should be judged REAL; any other finding
(for example a bare import warning) should be judged FALSE_ALARM.

Usage:
    python reviewer/score.py ground_truth.json triage_llama.json triage_qwen.json triage_gemma.json
"""

import json
import os
import sys


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def expected_verdict(gt, finding):
    vuln_lines = gt.get(finding["file"], [])
    return "REAL" if finding["line"] in vuln_lines else "FALSE_ALARM"


def score_file(gt, path):
    results = load(path)
    correct = scored = 0
    false_neg = false_pos = unusable = 0
    missed = []  # real bugs dismissed as false alarms

    for f in results:
        if f.get("duplicate_of"):
            continue
        verdict = f["triage"]["verdict"]
        if verdict in ("DUPLICATE",):
            continue
        if verdict not in ("REAL", "FALSE_ALARM"):
            unusable += 1          # ERROR or UNPARSED still counts as "not correct"
            scored += 1
            continue
        want = expected_verdict(gt, f)
        scored += 1
        if verdict == want:
            correct += 1
        elif want == "REAL":       # a real bug called a false alarm
            false_neg += 1
            missed.append(f"{f['file']}:{f['line']}")
        else:                      # a false alarm called real
            false_pos += 1

    return {
        "name": os.path.basename(path),
        "scored": scored, "correct": correct,
        "false_neg": false_neg, "false_pos": false_pos, "unusable": unusable,
        "missed": missed,
    }


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        raise SystemExit(1)
    gt = {k: v for k, v in load(sys.argv[1]).items() if not k.startswith("_")}

    rows = [score_file(gt, p) for p in sys.argv[2:]]

    print(f"{'triage run':<22}{'accuracy':>12}{'missed real':>14}{'false alarms kept':>20}{'unusable':>11}")
    for r in rows:
        acc = f"{r['correct']}/{r['scored']} ({100*r['correct']//r['scored'] if r['scored'] else 0}%)"
        print(f"{r['name']:<22}{acc:>12}{r['false_neg']:>14}{r['false_pos']:>20}{r['unusable']:>11}")

    print("\nReal vulnerabilities each run dismissed as false alarms:")
    for r in rows:
        print(f"  {r['name']}: {', '.join(r['missed']) if r['missed'] else 'none'}")


if __name__ == "__main__":
    main()
