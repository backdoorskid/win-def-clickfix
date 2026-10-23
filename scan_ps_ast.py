#!/usr/bin/env python3
import re
import sys

from dfcore import decode_b64_powershell

CMD_RE = re.compile(r"(?<![\w-])([A-Za-z][\w-]+)(?:\s|$|[|;])")
MEMBER_RE = re.compile(r"\.([A-Za-z][\w]+)\s*\(")

SUSPECT_CMDS = {
    "invoke-expression": "Invoke-Expression", "iex": "Invoke-Expression (iex)",
    "invoke-command": "Invoke-Command", "icm": "Invoke-Command (icm)",
    "invoke-webrequest": "Invoke-WebRequest", "iwr": "Invoke-WebRequest (iwr)",
    "invoke-restmethod": "Invoke-RestMethod", "irm": "Invoke-RestMethod (irm)",
    "downloadstring": "DownloadString", "downloadfile": "DownloadFile",
    "new-object": "New-Object (instantiation)", "add-type": "Add-Type (in-memory compile)",
    "start-process": "Start-Process", "start-job": "Start-Job", "set-mppreference": "Defender tamper",
    "add-mppreference": "Defender exclusion tamper", "schtasks": "scheduled task",
    "reg": "registry write", "cmd": "cmd invocation", "powershell": "nested powershell",
    "certutil": "certutil LOLBin", "curl": "curl download", "wmic": "WMI exec",
}
SUSPECT_MEMBERS = {
    "load": "[Reflection.Assembly]::Load (reflective load)",
    "loadwithpartialname": "Assembly.LoadWithPartialName",
    "frombase64string": "FromBase64String",
    "getstring": "Encoding.GetString",
    "createinstance": "Activator.CreateInstance",
    "run": "shell .Run()", "exec": "shell .Exec()",
}


def decode_payloads(cmd):
    return [(how, text) for text, how in decode_b64_powershell(cmd)]


def analyze_ast(script):
    low = script.lower()
    out = []
    for cmd in CMD_RE.findall(script):
        key = cmd.lower()
        if key in SUSPECT_CMDS:
            out.append(("ps_ast", f"cmdlet/command: {SUSPECT_CMDS[key]}"))
    for mem in MEMBER_RE.findall(script):
        key = mem.lower()
        if key in SUSPECT_MEMBERS:
            out.append(("ps_ast", f"member: {SUSPECT_MEMBERS[key]}"))
    if re.search(r"\[char\[\]\]|\[char\]\s*0x|\[char\]\s*\d+", low):
        out.append(("ps_ast", "char[] / [char] literal obfuscation"))
    if re.search(r"-bxor|-join|-split|-replace", low):
        out.append(("ps_ast", "string algebra (-bxor/-join/-split/-replace)"))
    if re.search(r"\[system\.convert\]|\[convert\]", low):
        out.append(("ps_ast", "[Convert] cast"))
    if re.search(r"&\s*\(|&\s*\$|&\s*['\"]", script):
        out.append(("ps_ast", "call operator (&) invocation"))
    if re.search(r"-\s*(join|f)\b|\{0\}|\{1\}", low):
        out.append(("ps_ast", "format/reverse operator"))
    if re.search(r"get-childitem\s+-recurse|ls\s+-r|\bdir\b", low):
        out.append(("ps_ast", "recursive enumeration"))
    return out


def main():
    try:
        cmd = input("Win+R command (may contain -EncodedCommand)> ").strip()
    except (EOFError, KeyboardInterrupt):
        print(); return 1
    if not cmd:
        print("no input"); return 1

    payloads = decode_payloads(cmd)
    print("\n== decoded payloads ==")
    if not payloads:
        print("  (none) — scanning argument text as-is")
        payloads = [("literal", cmd)]

    allhits = []
    for how, body in payloads:
        print(f"\n  --- {how} ---")
        print("  " + body[:400].replace("\n", "\n  "))
        for d, w in analyze_ast(body):
            allhits.append((how, w))

    print("\n== AST walk ==")
    if allhits:
        print("VERDICT: FLAGGED")
        print("  detection : Trojan:PowerShell/<family>")
        for how, w in sorted(set(allhits)):
            print(f"    [{how}] {w}")
    else:
        print("VERDICT: CLEAN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
