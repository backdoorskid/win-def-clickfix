#!/usr/bin/env python3
import re
import sys

WSH_RULES = [
    (r"createobject\s*\(\s*['\"]wscript\.shell", "CreateObject(WScript.Shell)"),
    (r"createobject\s*\(\s*['\"]shell\.application", "CreateObject(Shell.Application)"),
    (r"createobject\s*\(\s*['\"]msxml2\.|new\s+activexobject\(\s*['\"]msxml2\.",
     "MSXML HTTP object"),
    (r"xmlhttp|serverxmlhttp|\.open\s+\"get\"|\.send\b", "HTTP GET in script"),
    (r"adodb\.stream|\.savetofile|\.writetext|\.readtext", "ADODB.Stream disk write"),
    (r"\.run\s*\(|\.exec\s*\(|\.shellexecute\s*\(", "shell Run/Exec/ShellExecute"),
    (r"wscript\.shell|shell\.application", "shell object"),
    (r"getobject\s*\(\s*['\"]winmgmts:", "WMI via GetObject"),
    (r"winmgmts:|win32_process", "WMI process creation"),
    (r"executeglobal|\beval\s*\(|executescript", "dynamic code execution"),
    (r"chr\s*\(\s*\d+\s*\)|fromcharcode|charcodeat", "char-code obfuscation"),
    (r"[A-Za-z0-9+/]{200,}={0,2}", "large embedded base64 blob"),
    (r"https?://|ftp://", "remote URL"),
    (r"deletefile|filesystemobject|\.copyfile", "file system manipulation"),
    (r"environ\s*\(\s*['\"]temp|specialfolders", "temp path / special folder"),
    (r"\.hta\b|<hta:", "HTA application"),
]


def analyze_wsh(body):
    out = []
    for rx, why in WSH_RULES:
        if re.search(rx, body, re.I):
            out.append(("wsh", why))
    return out


def main():
    print("script-host payload scan (mshta/cscript/wscript; paste; blank to finish)")
    body = []
    while True:
        try:
            line = input("script> ")
        except (EOFError, KeyboardInterrupt):
            break
        if line == "":
            break
        body.append(line)
    text = "\n".join(body)

    hits = analyze_wsh(text)
    print("\n== script-host scan ==")
    if hits:
        print("VERDICT: FLAGGED")
        print("  detection : Trojan:Script/<family> (mshta/WSH)")
        for d, w in sorted(set(hits)):
            print(f"    - {w}")
    else:
        print("VERDICT: CLEAN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
