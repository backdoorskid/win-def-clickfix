#!/usr/bin/env python3
import re
import sys

from dfcore import normalize_cmdline

PS_RULES = [
    # cradles
    (r"invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b", "web request cradle"),
    (r"(new-object|new-object\s+system\.net\.webclient|net\.webclient)", "WebClient object"),
    (r"downloadstring|downloadfile|downloaddata", "download method"),
    (r"start-bitstransfer|bitsadmin\s+/(transfer|addfile|create)", "BITS transfer"),
    # execution
    (r"invoke-expression|\biex\b|iex\s*\(", "Invoke-Expression"),
    (r"invoke-command|icm\b", "Invoke-Command"),
    (r"start-process|saps\b|start-job", "process/job start"),
    (r"&-?\s*\$?\w+|&\s*\(", "call operator invocation"),
    # obfuscation
    (r"-join\s*\[char|\[char\[\]\]", "char[] join"),
    (r"-bxor|-replace\s+'[^']+'\s*,\s*''", "xor/replace deobfuscation"),
    (r"`[a-z]", "backtick escape"),
    (r"'{2,}|\"{2,}", "quote padding"),
    (r"\[convert\]::frombase64string|frombase64string", "FromBase64String"),
    (r"\[system\.text\.encoding\]::", "encoding object"),
    (r"\$\{?[a-z0-9_]+\}?\s*-\s*[a-z]", "string reversal/arithmetic trick"),
    # reflection/in-memory
    (r"\[reflection\.assembly\]::load|assembly\.loadwithpartialname", "reflective load"),
    (r"add-type", "Add-Type compile"),
    (r"invoke-obfuscation|out-encryptedscript", "known obfuscation framework"),
    # defense evasion
    (r"set-mppreference|add-mppreference|exclusionpath", "Defender tamper (ExclusionPath)"),
    (r"set-executionpolicy|bypass|-nop", "execution policy bypass"),
    (r"amsiinitfailed|amsiutils|amsi\.dll", "AMSI tamper"),
]


def analyze_ps(cmd):
    variants, notes, tags = normalize_cmdline(cmd)
    hay = (variants["lower"] + "\n" + variants["resolved"]).lower()
    hits = [why for rx, why in PS_RULES if re.search(rx, hay)]
    obf = sum(1 for h in hits if "obfusc" in h or "join" in h or "base64" in h
              or "escape" in h or "padding" in h or "trick" in h)
    return hits, obf


def main():
    try:
        cmd = input("powershell cmdline> ").strip()
    except (EOFError, KeyboardInterrupt):
        print(); return 1
    if not cmd:
        print("no input"); return 1

    variants, notes, tags = normalize_cmdline(cmd)
    hits, obf_score = analyze_ps(cmd)

    print("\n== PowerShell deep scan ==")
    print(f"  tags  : {' '.join(tags) if tags else '-'}")
    print(f"  deobf : {', '.join(notes) if notes else '-'}")
    print(f"  hits  : {len(hits)}  (obfuscation-weighted: {obf_score})")
    for h in sorted(set(hits)):
        print(f"    - {h}")

    if hits:
        print("\nVERDICT: FLAGGED")
        fam = "AmsiBypazz" if any("AMSI" in h for h in hits) else \
              "EncScript" if obf_score >= 2 else "RevShellz"
        print(f"  detection : Trojan:PowerShell/{fam}")
    elif obf_score:
        print("\nVERDICT: SUSPICIOUS (VirTool:Win32/Obfuscator.PN!)")
    else:
        print("\nVERDICT: CLEAN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
