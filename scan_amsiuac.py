#!/usr/bin/env python3
import re
import sys

from scan_cmdline import analyze

REMOTE = re.compile(r"https?://|\\\\|ftp://", re.I)
TEMP = re.compile(r"\\temp\\|\\appdata\\|%temp%|/tmp/", re.I)
SCRIPT_HOST = re.compile(r"powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|msiexec", re.I)


def scan_exe(cmdline):
    hits = []
    _, _, _, chits, cflag, _ = analyze(cmdline)
    if cflag:
        hits.append(f"elevated cmdline matches run-1 detector: {chits[0]['why']}")
    if REMOTE.search(cmdline):
        hits.append("elevation command references remote UNC/URL")
    if TEMP.search(cmdline) and SCRIPT_HOST.search(cmdline):
        hits.append("script/shell host executed from temp/appdata")
    return hits


def scan_msi(action, package_path, package_source, product):
    hits = []
    if REMOTE.search(package_source or "") or REMOTE.search(package_path or ""):
        hits.append("MSI install from remote source/URL")
    if re.search(r"unsign|unsigned", product or "", re.I):
        hits.append("unsigned/untrusted MSI product metadata")
    if action and action.lower() not in ("install", "maintenance", "update", "uninstall"):
        hits.append(f"suspicious MSI action '{action}'")
    return hits


def scan_com(server_binary, clsid):
    hits = []
    if server_binary and (TEMP.search(server_binary) or REMOTE.search(server_binary)):
        hits.append("COM server binary from temp/remote path")
    if server_binary and not re.search(r"\.(dll|exe)$", server_binary, re.I):
        hits.append("COM server binary with unexpected extension")
    return hits


def scan_ax(install_path, source_url):
    hits = []
    if REMOTE.search(source_url or ""):
        hits.append("ActiveX/install from remote URL (AX_SOURCEURL)")
    if install_path and TEMP.search(install_path):
        hits.append("ActiveX install to temp path")
    return hits


def scan_pkg(appname, cmdline, famname):
    hits = []
    if cmdline:
        _, _, _, chits, cflag, _ = analyze(cmdline)
        if cflag:
            hits.append(f"packaged-app cmdline detector: {chits[0]['why']}")
    if re.search(r"powershell|cmd|mshta", cmdline or "", re.I):
        hits.append("packaged app launching a shell host")
    return hits


def main():
    print("AMSI-UAC elevation scan")
    try:
        typ = (input("type (exe/com/msi/ax/pkg)> ").strip() or "exe").lower()
        trust = (input("trust state (trusted/untrusted/blocked) [untrusted]> ").strip() or "untrusted").lower()
    except (EOFError, KeyboardInterrupt):
        print(); return 1

    hits = []
    try:
        if typ == "exe":
            hits = scan_exe(input("ELEVATION command line> "))
        elif typ == "msi":
            hits = scan_msi(input("MSI action> "), input("MSI package path> "),
                            input("MSI package source> "), input("MSI product name> "))
        elif typ == "com":
            hits = scan_com(input("COM server binary> "), input("COM CLSID> "))
        elif typ == "ax":
            hits = scan_ax(input("AX install path> "), input("AX source url> "))
        elif typ == "pkg":
            hits = scan_pkg(input("Pkg app name> "), input("Pkg cmdline> "),
                            input("Pkg family name> "))
        else:
            print("unknown type"); return 1
    except (EOFError, KeyboardInterrupt):
        print(); return 1

    if trust == "blocked":
        hits.append("AMSI_UAC_TRUSTSTATE=BLOCKED")
    if trust == "untrusted":
        hits.append("AMSI_UAC_TRUSTSTATE=UNTRUSTED")

    print("\n== AMSI-UAC scan ==")
    print(f"  type  : {typ}")
    print(f"  trust : {trust}")
    if hits:
        print("\nVERDICT: FLAGGED (elevation blocked)")
        print("  detection : AMSI_UAC / Behavior:Win32/UAC elevation")
        for h in hits:
            print(f"    - {h}")
    else:
        print("\nVERDICT: ALLOWED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
