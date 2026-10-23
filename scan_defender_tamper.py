#!/usr/bin/env python3
import re
import sys

from dfcore import normalize_cmdline

RULES = [
    (r"set-mppreference\s+.*disable(realtimemonitoring|behaviormonitoring|ioavprotection|scriptscanning|antispyware|blockatfirstsight)",
     "Set-MpPreference disable protection"),
    (r"add-mppreference\s+.*-exclusion(path|process|extension|ipaddress)",
     "Add-MpPreference exclusion"),
    (r"set-mppreference\s+.*-exclusion", "Set-MpPreference exclusion"),
    (r"set-mppreference\s+.*disable", "Set-MpPreference disable flag"),
    (r"sc(\.exe)?\s+(stop|config|delete)\s+(windefend|wuauserv|sense|mdcoresvc|securityhealthservice)",
     "stop/tamper Defender service"),
    (r"net\s+stop\s+(windefend|mpssvc|sense)", "net stop security service"),
    (r"taskkill\s+.*(msmpeng|windefend|nissrv)", "kill AV process"),
    (r"reg\s+(add|delete)\s+.*windows\s+defender", "registry tamper on Windows Defender key"),
    (r"reg\s+delete\s+.*\\run\b", "remove Run entries"),
    (r"netsh\s+(adv?firewall|firewall).*(off|disable)", "disable firewall"),
    (r"vssadmin\s+delete\s+shadows|wbadmin\s+delete\s+catalog|wmic\s+shadowcopy\s+delete",
     "delete shadow copies"),
    (r"bcdedit\s+/set\s+.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)",
     "disable recovery/boot"),
    (r"set-executionpolicy\s+(bypass|unrestricted)", "loosen execution policy"),
    (r"fsutil\s+behavior\s+set", "fsutil behavior tamper"),
    (r"wevtutil\s+cl|clear-eventlog", "clear event log"),
    (r"disable-windowsoptionalfeature", "disable protection feature"),
]


def analyze_tamper(cmd):
    variants, notes, tags = normalize_cmdline(cmd)
    hay = (variants["resolved"] + "\n" + variants["lower"])
    out = []
    for rx, why in RULES:
        if re.search(rx, hay, re.I):
            out.append(("tamper", why))
    return out


def main():
    try:
        cmd = input("Win+R command line> ").strip()
    except (EOFError, KeyboardInterrupt):
        print(); return 1
    hits = analyze_tamper(cmd)
    print("\n== security-tamper scan ==")
    if hits:
        print("VERDICT: FLAGGED")
        print("  detection : Trojan:Win32/<family> (tamper/impact)")
        for d, w in sorted(set(hits)):
            print(f"    - {w}")
    else:
        print("VERDICT: CLEAN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
