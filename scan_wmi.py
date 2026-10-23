#!/usr/bin/env python3
import re
import sys

from scan_cmdline import analyze

RULES = [
    (r"wmic(\.exe)?\s+.*process\s+call\s+create", "wmic process call create"),
    (r"win32_process.*create|create\s*\(\s*['\"].*cmd", "Win32_Process.Create"),
    (r"invoke-wmimethod|invoke-cimmethod", "Invoke-WmiMethod / Invoke-CimMethod"),
    (r"\[wmiclass\]|\[wmi\]::|get-wmiobject\s+win32_process", "WMI class instantiation"),
    (r"\bwmiclass\b.*microsoft\.win32_process", "WMI process class"),
    (r"mmc20\.application|shellbrowserwindow|shell\.application", "DCOM ShellExecute object"),
    (r"excel\.application|outlook\.application|word\.application", "DCOM Office object"),
    (r"createobject\s*\(\s*['\"]wscript\.shell", "CreateObject(WScript.Shell)"),
    (r"\.document\.application.*shell", "DDE / ShellExecute via Office"),
    (r"mofcomp(\.exe)?|\.mof\b", "MOF compilation (WMI persistence/exec)"),
    (r"win32_processstarttrace|__eventfilter|commandlineeventconsumer",
     "WMI event subscription primitive"),
]


def analyze_wmi(line):
    hay = line.lower()
    hits = [why for rx, why in RULES if re.search(rx, hay)]
    _, _, _, chits, cflag, _ = analyze(line)
    if cflag:
        hits.append(f"embedded cmdline detector: {chits[0]['why']}")
    return hits


def main():
    try:
        line = input("wmi/com command> ").strip()
    except (EOFError, KeyboardInterrupt):
        print(); return 1
    if not line:
        print("no input"); return 1
    hits = analyze_wmi(line)
    print("\n== WMI/DCOM execution scan ==")
    if hits:
        print("VERDICT: FLAGGED")
        print("  detection : Trojan:Win32/<family>  (BM_WMIExecMethod)")
        for h in sorted(set(hits)):
            print(f"    - {h}")
    else:
        print("VERDICT: CLEAN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
