#!/usr/bin/env python3
import re
import sys

from dfcore import normalize_cmdline

# (binary regex, [ (arg pattern, why) ... ])
LOLBINS = {
    r"rundll32(\.exe)?$": [
        (r"javascript:|\.js\b|\.jse\b", "rundll32 javascript: execution"),
        (r"\burl\.dll|ieframe", "rundll32 url.dll (open/launch)"),
        (r"\\\\|https?://", "rundll32 remote/UNC DLL"),
        (r",\s*\w+", "rundll32 exported-function call"),
    ],
    r"regsvr32(\.exe)?$": [
        (r"/i:https?://", "regsvr32 remote scriptlet (squiblydoo)"),
        (r"scrobj\.dll", "regsvr32 scriptlet COM (squiblydoo)"),
        (r"/s\b", "regsvr32 silent register"),
    ],
    r"mshta(\.exe)?$": [
        (r"https?://", "mshta remote HTA"),
        (r"javascript:|vbscript:", "mshta inline script"),
        (r"\.hta\b", "mshta HTA drop"),
    ],
    r"msiexec(\.exe)?$": [
        (r"/i\s+https?://", "msiexec remote MSI install"),
        (r"/q(n|b|\b)", "msiexec silent install"),
        (r"\\\\", "msiexec UNC MSI"),
    ],
    r"certutil(\.exe)?$": [
        (r"-urlcache|-verifyctl", "certutil download cradles"),
        (r"-decode|-decodehex", "certutil decode payload"),
    ],
    r"bitsadmin(\.exe)?$": [
        (r"/transfer|/addfile", "bitsadmin transfer"),
    ],
    r"wmic(\.exe)?$": [
        (r"process\s+call\s+create", "wmic process create (spawn)"),
        (r"/node:", "wmic remote node"),
    ],
    r"msbuild(\.exe)?$": [ (r"\.xml|\.proj|\.csproj", "msbuild inline task execution") ],
    r"installutil(\.exe)?$": [ (r"/logfile=|/U\b", "installutil proxy .NET exec") ],
    r"forfiles(\.exe)?$": [ (r"/c\s+", "forfiles proxy exec") ],
    r"pcalua(\.exe)?$": [ (r"-a\s+", "pcalua proxy exec") ],
    r"conhost(\.exe)?$": [ (r"--headless|\.exe", "conhost headless spawn (ClickFix variant)") ],
    r"explorer(\.exe)?$": [ (r"\.(exe|ps1|vbs|bat|cmd|url)\b|https?://", "explorer launching a file/URL directly") ],
    r"curl(\.exe)?$": [ (r"-o\s+\S+|-O\b|https?://\S+\.(exe|dll|ps1|bat|cmd|vbs|js|jse|hta|scr|zip|7z|rar)\b",
                         "curl download/exec") ],
    r"certoc(\.exe)?$": [ (r"-LoadDll|-TP", "certoc download/exec") ],
}


def split_bin(cmd):
    m = re.match(r'\s*"?([^"\s]+)"?\s*(.*)', cmd.strip())
    return (m.group(1), m.group(2)) if m else (cmd, "")


def analyze_lolbin(cmd):
    variants, notes, tags = normalize_cmdline(cmd)
    flat = variants["flat"]
    binary, args = split_bin(cmd)
    bname = binary.replace("\\", "/").split("/")[-1].lower()
    hits = []
    for brx, pats in LOLBINS.items():
        if re.search(brx, bname) or re.search(brx, flat):
            for arx, why in pats:
                if re.search(arx, flat, re.I) or re.search(arx, args, re.I):
                    hits.append(why)
    return bname, args, hits


def main():
    try:
        cmd = input("command line> ").strip()
    except (EOFError, KeyboardInterrupt):
        print(); return 1
    if not cmd:
        print("no input"); return 1

    bname, args, hits = analyze_lolbin(cmd)
    print("\n== LOLBin matrix ==")
    print(f"  binary : {bname}")
    print(f"  args   : {args[:200]}")
    if hits:
        print("\nVERDICT: FLAGGED")
        print(f"  detection : Trojan:Win32/{bname.replace('.exe', '') or 'LOLBin'}")
        for h in sorted(set(hits)):
            print(f"    - {h}")
    else:
        print("\nVERDICT: CLEAN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
