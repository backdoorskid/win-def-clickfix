#!/usr/bin/env python3
import re
import sys

from dfcore import normalize_cmdline


def R(rx, detector, family, why, flags=re.I):
    return {"re": re.compile(rx, flags), "detector": detector, "family": family, "why": why}


RULES = [
    R(r"-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}", "ml", "Commando",
      "PowerShell -EncodedCommand with base64 blob"),
    R(r"-command\s+.{0,80}(iex|invoke-expression|\.\s*\()", "ml", "Commando",
      "inline -Command invoking iex/Invoke-Expression"),
    R(r"(iex|invoke-expression)\s*[\(\s']", "ml", "Commando",
      "Invoke-Expression / iex execution"),
    R(r"iex\s*\(\s*\(?new-object\s+net\.webclient", "sig", "ClickFix",
      "IEX + Net.WebClient download cradle"),

    # ---- download cradles ----
    R(r"(downloadstring|downloadfile|downloaddata|net\.webclient|invoke-webrequest|\biwr\b|\birm\b)",
      "sig", "ClickFix", "remote download cradle"),
    R(r"(curl|wget)\b.{0,160}(\.(exe|dll|ps1|bat|cmd|vbs|js|jse|wsf|hta|scr|zip|7z|rar)\b"
      r"|&&|;\s*\S+|\|\s*\S+|-[oO]\s+\S+)",
      "sig", "ClickFix", "curl/wget fetch of a payload or fetch-and-run"),
    R(r"start-bitstransfer|bitsadmin\s+/transfer", "behavior", "BITS", "BITS-based download"),
    R(r"certutil\s+-urlcache|certutil\s+-decode", "sig", "Certutil", "certutil download/decode (LOLBin)"),
    R(r"mshta\s+(https?://|javascript:|vbscript:)", "sig", "Mshta", "mshta remote/inline script"),

    # ---- hidden window / execution policy bypass ----
    R(r"-w(indowstyle)?\s+hid(den)?\b", "ml", "Commando", "hidden window (-w hidden)"),
    R(r"-nop(rofile)?\b|-noninteractive\b", "ml", "Commando", "PowerShell no-profile/non-interactive"),
    R(r"-exec(utionpolicy)?\s+bypass\b", "ml", "Commando", "ExecutionPolicy bypass"),

    # ---- LOLBins / proxy exec ----
    R(r"rundll32(\.exe)?\s+\S*\s*,?\s*(javascript|url|shell32|\\\\)", "sig", "Rundll32",
      "rundll32 with script/URL or UNC argument"),
    R(r"regsvr32(\.exe)?\s+.{0,40}(/i:http|scrobj)", "sig", "Regsvr32", "regsvr32 scriptlet (squiblydoo)"),
    R(r"msiexec\s+/i\s+https?://", "sig", "Msiexec", "msiexec remote MSI"),
    R(r"forfiles\s+/c\s+.{0,40}(cmd|powershell)", "sig", "Forfiles", "forfiles proxy exec"),
    R(r"conhost(\.exe)?\s+--headless", "sig", "ClickFix", "conhost headless (ClickFix variant)"),

    # ---- script-host / shell spawn chains ----
    R(r"(wscript|cscript)\s+.{0,40}https?://", "sig", "ScriptHost", "script host remote script"),
    R(r"cmd(\.exe)?\s*/c\s+.{0,40}powershell", "behavior", "Spawn", "cmd -> powershell chain"),

    # ---- AMSI / PowerShell content side ----
    R(r"amsi(utils|scanbuffer|\.dll|initfailed)|amsiinitfailed|setthreadpool", "amsi", "AmsiBypazz",
      "AMSI-related symbol in script body"),
    R(r"frombase64string|convert::frombase64string", "amsi", "EncScript", "FromBase64String in script body"),
    R(r"-[eE]\s*\(|\[char\[\]\]|\[Convert\]", "amsi", "EncScript", "char/Convert obfuscation"),

    # ---- obfuscation idioms ----
    R(r"fromcharcode|charcodeat", "ml", "JScriptObf", "char-code obfuscation present"),
    R(r"\bsplit\b.{0,40}\bjoin\b|\breplace\b.{0,40}\breplace\b", "ml", "JScriptObf",
      "split/join or replace chains"),

    # ---- script-host (JS/VBS) bodies ----
    R(r"activexobject\s*\(\s*['\"]wscript\.shell", "sig", "ScriptHost", "ActiveXObject(WScript.Shell) host abuse"),
    R(r"new\s+activexobject|wscript\.shell|shell\.application|shell\.run",
      "sig", "ScriptHost", "WScript/Shell ActiveX abuse"),
    R(r"\.run\s*\(|\.exec\s*\(|\.shellexecute\s*\(", "behavior", "ScriptHost",
      "shell Run/Exec/ShellExecute spawn"),
    R(r"xmlhttp|msxml2\.|winhttp|adodb\.stream", "sig", "ScriptHost", "script-host HTTP/stream object"),

    # ---- ASR-style ----
    R(r"winword|excel|powerpnt", "asr", "ASR", "Office host in command line (ASR Office Block)"),
]

DEOBF_WEIGHT = 1  # each deobfuscation idiom nudges the ML score


def analyze(cmdline: str):
    variants, notes, tags = normalize_cmdline(cmdline)
    hay = " \n ".join((variants["lower"], variants["flat"], variants["raw"].lower()))
    hits = []
    for rule in RULES:
        m = rule["re"].search(hay)
        if m:
            hits.append({"detector": rule["detector"], "family": rule["family"],
                         "why": rule["why"], "match": m.group(0)[:120]})
    order = {"sig": 0, "amsi": 1, "behavior": 2, "ml": 3, "asr": 4}
    hits.sort(key=lambda h: order.get(h["detector"], 9))
    flagged = bool(hits)
    score = len(hits) + (DEOBF_WEIGHT * len(notes))
    return variants, notes, tags, hits, flagged, score


def verdict(hits, flagged, score, tags):
    if not flagged:
        if score >= 3:
            return "SUSPICIOUS", "VirTool:Win32/Obfuscator.PN!", \
                   "heavy obfuscation idioms, no explicit family rule matched"
        return "CLEAN", None, "no run-1 detector matched"
    top = hits[0]
    name = {
        "sig": f"Trojan:Win32/{top['family']}",
        "ml": f"Trojan:Win32/{top['family']}.A!ml",
        "behavior": f"Trojan:Win32/{top['family']}.A!MTB",
        "amsi": f"Trojan:PowerShell/{top['family']}",
        "asr": f"ASR/{top['family']}",
    }.get(top["detector"], f"Trojan:Win32/{top['family']}")
    return "FLAGGED", name, top["why"]


def main():
    try:
        cmd = input("command line> ").strip()
    except (EOFError, KeyboardInterrupt):
        print(); return 1
    if not cmd:
        print("no input"); return 1

    variants, notes, tags, hits, flagged, score = analyze(cmd)
    v, name, why = verdict(hits, flagged, score, tags)

    print("\n== normalized surface ==")
    print("  tags      :", " ".join(tags) if tags else "-")
    print("  deobf     :", ", ".join(notes) if notes else "-")
    print("  resolved  :", variants["resolved"][:400])
    print("  flat      :", variants["flat"][:400])
    if flagged:
        print("\n== detectors fired ==")
        for h in hits:
            print(f"  [{h['detector']:8}] {h['why']}  (match: {h['match']!r})")
    print(f"\nVERDICT: {v}")
    if name:
        print(f"  detection : {name}")
    print(f"  reason    : {why}")
    print(f"  score     : {score}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
