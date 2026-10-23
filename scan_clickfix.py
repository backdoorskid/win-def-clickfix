#!/usr/bin/env python3
import re
import sys

from dfcore import normalize_cmdline

# (regex, weight, label)
FINGERPRINT = [
    (r"powershell|pwsh", 1, "PowerShell launcher"),
    (r"\b(mshta|conhost|rundll32|regsvr32)\b", 1, "LOLBin/host launcher"),
    (r"-w(indowstyle)?\s+hid|\bhidden\b", 2, "hidden window"),
    (r"-nop(rofile)?|-noninteractive|-noni\b", 1, "non-interactive PowerShell"),
    (r"-e(xecutionpolicy)?\s*bypass|-ep\s+bypass", 2, "ExecutionPolicy bypass"),
    (r"-enc(odedcommand)?\b", 2, "encoded command"),
    (r"-c(ommand)?\b", 1, "inline -Command"),
    (r"iex\b|invoke-expression", 2, "Invoke-Expression"),
    (r"invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|downloadstring|downloadfile",
     2, "web download"),
    (r"curl\b|\(iwr|new-object\s+net\.webclient", 2, "curl/WebClient"),
    (r"https?://|ftp://", 1, "remote URL"),
    (r"-o\s+\S+\s*&&|&&\s*\S+\.(exe|bat|cmd|ps1)", 3, "download-and-execute chain"),
    (r"certutil\s+-urlcache|bitsadmin\s+/transfer", 2, "LOLBin download"),
    (r"conhost(\.exe)?\s+--headless", 3, "conhost headless (ClickFix variant)"),
    (r"mshta\s+https?://|mshta\s+javascript:", 3, "mshta remote/inline"),
    (r"start\s+https?://|start-process\s+.*http", 2, "staged start"),
    (r"verif(y|ication)|human|captcha|robot|\bcloudflare\b", 1, "lure wording copied into command"),
]

THRESHOLDS = {"strong": 6, "moderate": 3}


def analyze_clickfix(cmd):
    variants, notes, tags = normalize_cmdline(cmd)
    hay = (variants["lower"] + "\n" + variants["resolved"]).lower()
    score = 0
    labels = []
    for rx, w, lbl in FINGERPRINT:
        if re.search(rx, hay, re.I):
            score += w
            labels.append(lbl)
    # one-liner shape: long single line with no newline
    if len(cmd) > 90 and "\n" not in cmd and ("powershell" in hay or "mshta" in hay):
        score += 2
        labels.append("long single-line one-liner")
    return score, labels


def main():
    try:
        cmd = input("Win+R command line> ")
    except (EOFError, KeyboardInterrupt):
        print(); return 1
    score, labels = analyze_clickfix(cmd)
    print("\n== ClickFix fingerprint ==")
    print(f"  score : {score}")
    for l in dict.fromkeys(labels):
        print(f"    + {l}")
    if score >= THRESHOLDS["strong"]:
        print("\nVERDICT: FLAGGED  (Trojan:Win32/Commando.A!ml / ClickFix!MTB)")
    elif score >= THRESHOLDS["moderate"]:
        print("\nVERDICT: SUSPICIOUS  (threshold-adjacent)")
    else:
        print("\nVERDICT: CLEAN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
