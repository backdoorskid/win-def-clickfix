#!/usr/bin/env python3
import re
import sys

from scan_cmdline import analyze

BLOB_SIGN = re.compile(
    r"(https?://\S+\.(exe|dll|ps1|bat|cmd|vbs|js|jse|wsf|hta|scr|zip|7z|rar)\b"
    r"|\\\\[A-Za-z0-9._-]+\\[^\s]"
    r"|(?:\\x[0-9a-fA-F]{2}){4,}"
    r"|[A-Za-z0-9+/]{120,}={0,2})", re.I)


def _score_command(cmd):
    hits = []
    _, _, _, chits, cflag, _ = analyze(cmd)
    if cflag:
        hits.append(f"Run entry matches detector: {chits[0]['why']}")
    if BLOB_SIGN.search(cmd):
        hits.append("Run entry references a payload URL / encoded blob")
    return hits


def analyze_runmru(entries):
    out = []
    for slot, cmd in entries.items():
        for w in _score_command(str(cmd)):
            out.append(("runmru", f"[{slot}] {w}"))
    return out


CLIP_RISK = [
    (r"mshta:|javascript:|vbscript:|file:///", "clipboard carries an executable URI scheme"),
    (r"Start-Process|Invoke-Expression|IEX\(", "clipboard carries an execution primitive"),
    (r"powershell.*-e(nc|ncodedcommand)", "clipboard carries an encoded PowerShell command"),
    (r"<a\s+href|onclick|Copy to clipboard|Verify you are human|not a robot|"
     r"press.*(win|windows)\s*\+?\s*r|run\s+dialog", "clipboard carries ClickFix lure HTML/wording"),
    (r"\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){6,}|[A-Za-z0-9+/]{120,}={0,2}",
     "clipboard carries an encoded payload blob"),
]


def analyze_clipboard(text, fmt="text"):
    out = []
    for rx, why in CLIP_RISK:
        if re.search(rx, text, re.I):
            out.append(("clipboard", f"{fmt}: {why}"))
    for w in _score_command(text):
        out.append(("clipboard", f"{fmt}: {w}"))
    return out


def main():
    print("RunMRU / clipboard inspector")
    print("  lines 'slot=value' -> RunMRU; free text -> clipboard (blank to finish)")
    entries, blob = {}, []
    while True:
        try:
            line = input("> ").rstrip("\n")
        except (EOFError, KeyboardInterrupt):
            print(); break
        if line == "":
            break
        m = re.match(r"^([A-Za-z])=(.*)$", line)
        if m:
            entries[m.group(1)] = m.group(2)
        else:
            blob.append(line)

    hits = analyze_runmru(entries) if entries else []
    if blob:
        hits += analyze_clipboard("\n".join(blob), "clipboard")

    print("\n== RunMRU / clipboard scan ==")
    if entries:
        for k, v in entries.items():
            print(f"  MRU[{k}]: {v[:120]}")
    if hits:
        print("\nVERDICT: FLAGGED")
        print("  detection : Trojan:Win32/ClickFix (Run history / clipboard)")
        for d, w in hits:
            print(f"    - {w}")
    else:
        print("\nVERDICT: CLEAN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
