#!/usr/bin/env python3
import re
import sys

from dfcore import normalize_cmdline

CMDSHELL_RULES = [
    (r"\bcmd(\.exe)?\s+/[ck]\b", "cmd /c or /k execution"),
    (r"\bcmd(\.exe)?\s+/[ck]\s+.*(/c|/k|powershell|mshta|rundll32|regsvr32)",
     "nested shell invocation"),
    (r"&&|\|\|", "command chaining (&& / ||)"),
    (r"\|\s*(cmd|powershell|mshta|certutil|curl|bitsadmin)", "piped download/exec chain"),
    (r"(^|[^&])&\s*(cmd|powershell|mshta|rundll32|certutil|curl)", "&-chained shell command"),
    (r"%comspec%", "%COMSPEC% indirection"),
    (r"%windir%|%temp%|%appdata%|%public%", "environment-variable path indirection"),
    (r"\^[a-z]", "caret (^) escape obfuscation"),
    (r"!\w+!", "delayed-expansion (!var!) obfuscation"),
    (r"for\s+/f", "for /f token parsing"),
    (r"start\s+/min|start\s+\"\"|start\s+/b", "detached/minimized process start"),
    (r"echo\s+.*\|\s*cmd", "echo-pipe to cmd"),
]


def analyze_cmdshell(cmd):
    variants, notes, tags = normalize_cmdline(cmd)
    hay = (variants["resolved"] + "\n" + variants["raw"]).lower()
    hits = []
    for rx, why in CMDSHELL_RULES:
        if re.search(rx, hay, re.I):
            hits.append(("cmdshell", why))
    return hits


def main():
    try:
        cmd = input("cmd-shell command> ")
    except (EOFError, KeyboardInterrupt):
        print(); return 1
    hits = analyze_cmdshell(cmd)
    print("\n== cmd shell scan ==")
    print("  normalized:", normalize_cmdline(cmd)[0]["resolved"][:200])
    if hits:
        print("\nVERDICT: FLAGGED")
        for d, w in sorted(set(hits)):
            print(f"    - {w}")
    else:
        print("\nVERDICT: CLEAN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
