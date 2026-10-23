#!/usr/bin/env python3
"""report_lint.py — the three reasons a bug-bounty report gets thrown away, checked before you send it.

Most rejected reports are not wrong about the bug. They are wrong about the *report*:

  1. the structure is not the one the programme reads (its triager skims the sections in a
     fixed order, and a report in a different shape makes them hunt for the thread);
  2. the router claims something that was never measured — a word like "likely", "should",
     "could allow" where a number was needed;
  3. the limits are hidden. A report that hides its own gap loses everything the moment the
     gap is found by someone else; a report that states it survives.

This linter checks those three things, plus the arithmetic: it recomputes the CVSS base score
from the vector you pasted, so a vector that does not match your text cannot slip through.

  python3 report_lint.py report.md
  python3 report_lint.py report.md --style ywh          # YesWeHack's five sections
  python3 report_lint.py report.md --style hackerone
  python3 report_lint.py report.md --strict             # warnings also fail

Exit codes: 0 = clean; 1 = problems (or warnings with --strict); 2 = unreadable file.

No dependencies. The CVSS maths follows the CVSS v3.1 specification.
"""
import argparse
import re
import sys

STYLES = {
    "generic": ["## Summary", "## Evidence", "## Impact", "## Reproduction", "## Fix", "## Caveats"],
    "ywh": ["## Description", "## Exploitation", "## PoC", "## Risk", "## Remediation"],
    "hackerone": ["## Summary", "## Steps to Reproduce", "## Impact", "## Supporting Material"],
}

HEDGE = r"\b(likely|probably|possibly|should be|might|may be|i think|i believe|seems to|appears to)\b"
LIMIT_MARKERS = r"(not claimed|not demonstrated|not proven|caveat|limitation|did not|assume[sd]?|theoretical|candidate)"
FILLER = ("as an ai", "i hope this helps", "in conclusion", "it is worth noting that", "delve into")

# --- CVSS v3.1 base score ---------------------------------------------------
AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def roundup(x):
    """CVSS v3.1 Appendix A: round UP to one decimal, not to the nearest."""
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (i // 10000 + 1) * 10000 / 100000.0


def cvss_score(vec):
    """CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> (score, severity)"""
    parts = dict(p.split(":") for p in vec.split("/") if ":" in p)
    if parts.pop("CVSS", None) not in ("3.1", "3.0"):
        raise ValueError("not a CVSS v3 vector")
    sc = parts["S"] == "C"
    iss = 1 - (1 - CIA[parts["C"]]) * (1 - CIA[parts["I"]]) * (1 - CIA[parts["A"]])
    if sc:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    pr = (PR_C if sc else PR_U)[parts["PR"]]
    expl = 8.22 * AV[parts["AV"]] * AC[parts["AC"]] * pr * UI[parts["UI"]]
    if impact <= 0:
        score = 0.0
    else:
        raw = (min(1.08 * (impact + expl), 10) if sc else min(impact + expl, 10))
        score = roundup(raw)
    sev = ("none" if score == 0 else "low" if score < 4 else "medium" if score < 7
           else "high" if score < 9 else "critical")
    return score, sev


def lint(text, style):
    problems, warnings = [], []
    lines = text.splitlines()
    title = lines[0].lstrip("# ").strip() if lines else ""
    if not title:
        problems.append("no title on the first line")
    elif len(title) > 128:
        problems.append(f"title is {len(title)} chars, many platforms cap at 128")
    if title.lower().startswith(("bug report", "report", "finding", "vulnerability")):
        warnings.append('generic title: prefer "X does Y, so Z" with the effect')

    for sec in STYLES[style]:
        if sec not in text:
            problems.append(f"missing section for this style: {sec}")

    blocks = re.findall(r"```[a-z]*\n(.*?)```", text, re.S)
    if not blocks:
        warnings.append("no code blocks: paste the real command/output, not a description of it")
    elif not any(re.search(r"^\s*\$ ", b, re.M) for b in blocks):
        warnings.append("no code block shows a prompt (`$ ...`): put the command and its output")

    for f in FILLER:
        if f in text.lower():
            problems.append(f'filler phrase: "{f}"')

    hedges = sorted(set(m.group(0).lower() for m in re.finditer(HEDGE, text, re.I)))
    if hedges:
        warnings.append("hedging language where a measurement belongs: " + ", ".join(hedges[:6]))

    if not re.search(LIMIT_MARKERS, text, re.I):
        problems.append("no declared limit: state what you did NOT prove, or a reviewer will find it first")

    for m in re.finditer(r"CVSS:3\.[01]/[A-Z:/\w]+", text):
        vec = m.group(0)
        try:
            score, sev = cvss_score(vec)
        except Exception as e:
            problems.append(f"CVSS vector {vec} does not parse: {e}")
            continue
        stated = re.search(r"(\d\.\d)\s*(?:\(|\s|$)", text[m.end():m.end() + 40] or "")
        if stated:
            got = float(stated.group(1))
            if abs(got - score) > 0.05:
                problems.append(f"CVSS vector computes {score} ({sev}) but the text says {got}")

    digits = re.findall(r"\b\d[\d.,]*\b", text)
    if len(digits) < 3:
        warnings.append("almost no numbers: quantities are what make a report checkable")

    return title, problems, warnings


def main(argv):
    ap = argparse.ArgumentParser(description="Lint a bug-bounty report before you send it.")
    ap.add_argument("path")
    ap.add_argument("--style", default="generic", choices=sorted(STYLES))
    ap.add_argument("--strict", action="store_true", help="warnings also fail the run")
    ap.add_argument("--selftest", action="store_true", help="check the CVSS maths against known vectors")
    a = ap.parse_args(argv)

    if a.selftest:
        cases = {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H": 7.5,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L": 6.5,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N": 5.3,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
            "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.8,
        }
        bad = 0
        for vec, want in cases.items():
            got, sev = cvss_score(vec)
            ok = abs(got - want) < 0.05
            bad += 0 if ok else 1
            print(f"  {'ok ' if ok else 'BAD'} {vec} -> {got} ({sev}), expected {want}")
        print("selftest:", "all vectors correct" if not bad else f"{bad} wrong")
        return 0 if not bad else 1

    try:
        text = open(a.path, encoding="utf-8", errors="ignore").read()
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    title, problems, warnings = lint(text, a.style)
    print(f"{a.path}: {len(text)} chars · style={a.style}")
    print(f"  title: {title[:96]}")
    for p in problems:
        print(f"  x {p}")
    for w in warnings:
        print(f"  ! {w}")
    if not problems:
        print("  ok: ready to send")
    return 1 if problems or (a.strict and warnings) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
