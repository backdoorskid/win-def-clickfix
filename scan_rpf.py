#!/usr/bin/env python3
import re
import sys

from dfcore import normalize_cmdline, decode_b64_powershell

FILELESS = [
    (r"\[reflection\.assembly\]::load|\[system\.reflection\.assembly\]::load|assembly\.load",
     "reflective .NET assembly load"),
    (r"\badd-type\b|\bcodedomprovider\b|compileassemblyfromsource",
     "in-memory Add-Type / CodeDom compile"),
    (r"\[convert\]::frombase64string|frombase64string", "FromBase64String blob"),
    (r"virtualalloc|createthread|writeprocessmemory|ntcreatethread|\bwriteprocessmemory\b",
     "native memory-write / thread-create API"),
    (r"-join\s*\[char|\[char\[\]\]|\[byte\[\]\]|\+\s*\[char", "char/byte array assembly"),
    (r"invoke-expression|\biex\b", "Invoke-Expression of staged content"),
    (r"javascript:|vbscript:\s*function|mshtml\.dll", "in-host script engine (mshta/rundll32)"),
    (r"regsvr32\s+/i:http|scrobj\.dll", "remote scriptlet load"),
    (r"\bmsbuild\b|installutil|regasm|regsvcs", "proxy .NET execution LOLBin"),
]


def analyze_rpf(cmd):
    variants, notes, tags = normalize_cmdline(cmd)
    blob = (variants["lower"] + "\n" + variants["resolved"]).lower()
    hits = [why for rx, why in FILELESS if re.search(rx, blob)]
    staged = bool(decode_b64_powershell(cmd)) or re.search(r"-enc", cmd, re.I)
    if staged:
        hits.append("staged/encoded payload (RPF scans decoded pages)")
    engage = bool(hits) or bool(tags)
    return engage, sorted(set(hits))


def main():
    try:
        cmd = input("command line> ").strip()
    except (EOFError, KeyboardInterrupt):
        print(); return 1
    if not cmd:
        print("no input"); return 1

    variants, notes, tags = normalize_cmdline(cmd)
    engage, hits = analyze_rpf(cmd)

    print("\n== CmdLine RPF (memory page) scan ==")
    print("  tags     :", " ".join(tags) if tags else "-")
    print("  rpf      :", "ENGAGED" if engage else "not engaged")
    print("  page sizes: Rpf=0x40000(256KB) Jit=0x4d000 JitExe=0x4d000  (FUN_1809bedb0)")
    if hits:
        print("\n== fileless primitives ==")
        for h in hits:
            print(f"    - {h}")

    if len(hits) >= 2 or re.search(r"reflection|virtualalloc|writeprocessmemory|msbuild", 
                                   variants["lower"]):
        print("\nVERDICT: FLAGGED (in-memory detection)")
        print("  detection : Trojan:PowerShell/<stager>!MTB  (RPF memory scan)")
    elif engage:
        print("\nVERDICT: SUSPICIOUS (RPF engages; memory sig/ML decides)")
    else:
        print("\nVERDICT: CLEAN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
