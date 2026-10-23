#!/usr/bin/env python3
import re
import sys

from dfcore import normalize_cmdline
from scan_cmdline import analyze

PS_BAD = [
    (r"amsiinitfailed|amsiutils|amsi\.dll|amsiscanbuffer|amsi_context",
     "AMSI bypass / tamper symbol"),
    (r"\[ref\]\.assembly|gettype\(|setvalue\(|nonpublic",
     "reflection-based AMSI/CLR tamper"),
    (r"setthreadpool|hidedebugger|virtualprotect|writeprocessmemory",
     "native memory-patch API in script"),
    (r"frombase64string|convert::frombase64string",
     "FromBase64String decode"),
    (r"downloadstring|downloadfile|net\.webclient|invoke-webrequest|iwr\b",
     "remote download cradle"),
    (r"iex\b|invoke-expression", "Invoke-Expression"),
    (r"-join\s*\[char|\[char\[\]\]|\+\s*\[char", "char[] join obfuscation"),
    (r"bypass|executionpolicy", "ExecutionPolicy bypass"),
    (r"securerstring|securestring|convertto-securestring|-asplaintext",
     "credential/securestring handling"),
    (r"lsass|sam\b|ntds|minidump|comsvcs\.dll|procdump",
     "credential dumping primitive"),
    (r"net\.(tcpclient|sockets)|new-object system\.net",
     ".NET socket (reverse shell primitive)"),
]

JS_BAD = [
    (r"activexobject|wscript\.shell|shell\.application", "WScript/ActiveXObject host abuse"),
    (r"adodb\.stream|savetofile|writetext", "stream->disk write"),
    (r"xmlhttp|msxml2|winhttp", "HTTP client in script host"),
    (r"new\s+activexobject\(\s*['\"]wscript\.shell", "WScript.Shell spawn"),
]


def bom_check(raw: bytes):
    issues = []
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff") and b"\x00\x00" not in raw[:64]:
        if all(32 <= b < 127 for b in raw[:24] if b):
            issues.append("BOM Mismatch (UTF16-utf8)")
    if raw[:3] == b"\xef\xbb\xbf" and b"\x00" in raw[:32]:
        issues.append("BOM Mismatch (UTF8-utf16)")
    if raw[:2] in (b"\xfe\x00", b"\x00\xfe", b"\xff\xfe\x00\x00"):
        issues.append("Unsupported BOM")
    return issues


def analyze_amsi(body):
    hits = []
    for rx, why in PS_BAD:
        if re.search(rx, body, re.I):
            hits.append(why)
    for rx, why in JS_BAD:
        if re.search(rx, body, re.I):
            hits.append(why)
    return hits


def main():
    try:
        body = input("script body> ")
    except (EOFError, KeyboardInterrupt):
        print(); return 1
    if not body:
        print("no input"); return 1

    hits = analyze_amsi(body)
    boms = bom_check(body.encode("utf-8", "surrogatepass"))
    _, notes, tags, cmd_hits, cmd_flag, score = analyze(body)

    print("\n== AMSI content scan ==")
    print("  tags     :", " ".join(tags) if tags else "-")
    print("  bom      :", ", ".join(boms) if boms else "-")
    print("  script   :", ", ".join(sorted(set(hits))) if hits else "-")

    flagged = bool(hits) or cmd_flag or bool(boms)
    if flagged:
        fam = "AmsiBypazz" if any("AMSI" in h for h in hits) else \
              "RevShellz" if any("socket" in h for h in hits) else "EncScript"
        print("\nVERDICT: FLAGGED")
        print(f"  detection : Trojan:PowerShell/{fam}  (AMSI resmgr)")
        for h in hits:
            print(f"    - {h}")
        for h in cmd_hits:
            print(f"    - [cmdline/{h['detector']}] {h['why']}")
        if boms:
            print(f"    - PowerShellIssues: {', '.join(boms)}")
    else:
        print("\nVERDICT: CLEAN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
