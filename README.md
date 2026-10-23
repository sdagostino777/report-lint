# report-lint

Check a bug-bounty report for the three reasons reports actually get rejected — before you send it.

Most rejected reports are not wrong about the bug. They are wrong about the *report*:

1. the structure is not the one the programme reads, so the triager hunts for the thread;
2. the text claims something that was never measured (`likely`, `should`, `could allow` where a
   number belonged);
3. the limits are hidden. A report that hides its own gap loses everything when someone else finds
   the gap; a report that states it survives.

The linter checks those, and it also **recomputes the CVSS base score** from the vector you pasted,
so a vector that does not match your text cannot slip through.

```
$ python3 report_lint.py report.md --style ywh
report.md: 7888 chars · style=ywh
  title: Protocol 2.0 A.1.4: the ballot-validity proof does not enforce ...
  ! no code block shows a prompt (`$ ...`): put the command and its output
  ok: ready to send
```

## Use

```
python3 report_lint.py report.md                    # generic structure
python3 report_lint.py report.md --style ywh        # Description / Exploitation / PoC / Risk / Remediation
python3 report_lint.py report.md --style hackerone  # Summary / Steps to Reproduce / Impact / Supporting Material
python3 report_lint.py report.md --strict           # warnings fail too
python3 report_lint.py x --selftest                 # verify the CVSS maths
```

Styles are declared in one dict at the top of the file: add your platform's section list and it
works.

## The CVSS maths

`--selftest` runs six published vectors and fails if any score is off. It is worth running once:
the CVSS 3.1 rounding rule is *round up* to one decimal, not round-to-nearest, and getting it wrong
shifts scores by 0.1–0.5 — enough to change a severity band.

## What this is not

It does not write reports and it will not make a weak finding strong. It only refuses to let a
report go out with a section missing, a number invented, or a limit hidden.

MIT.
