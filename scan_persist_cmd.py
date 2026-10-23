#!/usr/bin/env python3
import re
import sys

from dfcore import normalize_cmdline

RULES = [
    (r"reg\s+add\s+.*\\currentversion\\run\b", "reg add Run key"),
    (r"reg\s+add\s+.*\\runonce\b", "reg add RunOnce key"),
    (r"new-itemproperty\s+.*\\currentversion\\run", "New-ItemProperty Run key"),
    (r"schtasks(\.exe)?\s+/create", "schtasks /create"),
    (r"register-scheduledtask|new-scheduledtask", "Register/New-ScheduledTask"),
    (r"sc(\.exe)?\s+create\b", "sc create service"),
    (r"new-service\b", "New-Service"),
    (r"wmic\s+.*startup\s+call\s+create", "WMI startup entry (wmic)"),
    (r"\\start menu\\programs\\startup|\\startup\\", "Startup folder drop"),
    (r"copy\s+.*\.(exe|bat|cmd|vbs|js|ps1)\s+.*startup", "copy into Startup"),
    (r"schtasks\s+/change\s+/tn", "modify existing scheduled task"),
    (r"bcdedit\s+/set\s+.*recoveryenabled", "bcdedit persistence"),
    (r"\\winlogon\\|\\winlogon\b|\buserinit\b|\\shell\\open\\command",
     "Winlogon/Userinit/shell-open hijack"),
    (r"attrib\s+\+h|\+s\s", "hide/attribute file"),
]


def analyze_persist(cmd):
    variants, notes, tags = normalize_cmdline(cmd)
    hay = (variants["resolved"] + "\n" + variants["lower"])
    out = []
    for rx, why in RULES:
        if re.search(rx, hay, re.I):
            out.append(("persist", why))
    return out


def main():
    try:
        cmd = input("Win+R command line> ").strip()
    except (EOFError, KeyboardInterrupt):
        print(); return 1
    hits = analyze_persist(cmd)
    print("\n== persistence-creation scan ==")
    if hits:
        print("VERDICT: FLAGGED")
        print("  detection : Trojan:Win32/<family> (persistence, behavior)")
        for d, w in sorted(set(hits)):
            print(f"    - {w}")
    else:
        print("VERDICT: CLEAN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
