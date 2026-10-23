#!/usr/bin/env python3
import re
import sys

from dfcore import normalize_cmdline

URL_RE = re.compile(r"(https?://[^\s\"'|;&]+|ftp://[^\s\"'|;&]+|\\\\[^\s\"'|;&]+)")
WRITE_RE = re.compile(
    r"(?:-o|--output|-outfile|-destination|-path|-uri)\s+(\S+)|"
    r"(?:>|>>)\s*(\S+)|"
    r"(?:out-file|set-content|add-content|new-item)\s+(\S+)|"
    r"(?:curl|wget|certutil|bitsadmin|iwr|invoke-webrequest)\b[^|;&]*", re.I)

FETCH_CMDS = re.compile(
    r"(curl|wget|invoke-webrequest|iwr|invoke-restmethod|irm|"
    r"start-bitstransfer|bitsadmin|certutil\s+-urlcache|"
    r"downloadstring|downloadfile|downloaddata|net\.webclient|"
    r"system\.net\.webclient|start-process\s+.*http)", re.I)

EXEC_AFTER = re.compile(
    r"(iex\b|invoke-expression|\|\s*(iex|powershell|cmd|bash|sh)\b|"
    r"&&\s*\S+\.(exe|bat|cmd|ps1|vbs|js|hta)\b|;\s*\S+\.(exe|bat|cmd|ps1)\b|"
    r"start-process\s+\S+\.(exe|ps1|bat|cmd)|\.(exe|bat|cmd|ps1)\b)", re.I)

DANGEROUS_TARGET = re.compile(
    r"\.(exe|dll|ps1|bat|cmd|vbs|js|jse|wsf|hta|scr|lnk|zip|7z|rar|iso|img)\b", re.I)


def analyze_download(cmd):
    variants, notes, tags = normalize_cmdline(cmd)
    hay = variants["resolved"] + "\n" + variants["raw"]
    out = []

    urls = URL_RE.findall(hay)
    fetches = bool(FETCH_CMDS.search(hay))
    executes = bool(EXEC_AFTER.search(hay))

    payload_url = [u for u in urls if DANGEROUS_TARGET.search(u)]
    if fetches and payload_url:
        out.append(("download", f"fetches a payload: {', '.join(sorted(set(payload_url)))[:180]}"))

    if fetches and executes:
        out.append(("download", "download-and-execute chain (fetch then run)"))

    writes = [g for tup in WRITE_RE.findall(hay) for g in tup if g]
    for w in writes:
        if DANGEROUS_TARGET.search(w):
            out.append(("download", f"writes an executable/archive target: {w}"))
        elif re.search(r"\\temp\\|\\appdata\\|\\public\\|\\programdata\\|/tmp/", w, re.I):
            out.append(("download", f"writes to a staging path: {w}"))

    if re.search(r"certutil\s+-urlcache|bitsadmin\s+/transfer|certutil\s+-decode", hay, re.I):
        out.append(("download", "LOLBin download (certutil/bitsadmin)"))
    return out


def main():
    try:
        cmd = input("Win+R command line> ").strip()
    except (EOFError, KeyboardInterrupt):
        print(); return 1
    hits = analyze_download(cmd)
    print("\n== download cradle scan ==")
    if hits:
        print("VERDICT: FLAGGED")
        print("  detection : Trojan:Win32/ClickFix")
        for d, w in sorted(set(hits)):
            print(f"    - {w}")
    else:
        print("VERDICT: CLEAN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
