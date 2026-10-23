#!/usr/bin/env python3
import os
import re
import sys

DEFAULT_RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")

_RULE_META = re.compile(r'detection_name = "([^"]*)"')
_RULE_THRESH = re.compile(r'threshold = "(-?\d+)"')
_RULE_STR = re.compile(r'^\s*\$(\w+)\s*=\s*(.+?)\s*//weight:\s*(-?\d+)')
_RULE_NAME = re.compile(r'^rule\s+(\S+)')
_RULE_COND = re.compile(r'condition:\s*(.*)', re.S)

GENERIC = {
    "powershell", "powershell.exe", "pwsh", "pwsh.exe", "cmd", "cmd.exe",
    "mshta", "mshta.exe", "rundll32", "rundll32.exe", "regsvr32", "regsvr32.exe",
    "cscript", "cscript.exe", "wscript", "wscript.exe", "bitsadmin", "bitsadmin.exe",
    "certutil", "certutil.exe", "certoc", "certoc.exe", "msiexec", "msiexec.exe",
    "schtasks", "schtasks.exe", "wevtutil", "wevtutil.exe", "whoami", "whoami.exe",
    "net", "net.exe", "net1.exe", "reg", "reg.exe", "curl", "curl.exe",
    "wget", "wget.exe", "wmic", "wmic.exe", "nslookup", "nslookup.exe",
    "ipconfig", "ipconfig.exe", "netstat", "netstat.exe", "tasklist", "tasklist.exe",
    "xcopy", "xcopy.exe", "robocopy", "robocopy.exe", "netsh", "netsh.exe",
    "vssadmin", "vssadmin.exe", "forfiles", "forfiles.exe", "installutil",
    "installutil.exe", "ping", "ping.exe", "runas", "runas.exe", "calc.exe",
    "mspaint.exe", "systeminfo", "systeminfo.exe", "quser.exe", "qwinsta.exe",
    "arp.exe", "nltest.exe", "winrs.exe", "credwiz.exe", "anydesk.exe",
    "7z.exe", "rar.exe", "conhost", "conhost.exe", "http", "https", "ftp",
    "bypass", "-accepteula", "mimikatz", "wscript.shell", "powershell.exe ",
    "cmd.exe ", "cmd ", "/bin/bash", "/bin/sh", "bash", "sh",
    "taskkill", "taskkill.exe", "sc", "sc.exe", "gpupdate", "gpupdate.exe",
    "gpresult", "gpresult.exe", "dir", "del", "copy", "move", "type", "echo",
    "findstr", "findstr.exe", "qprocess.exe", "dsquery.exe", "dsget.exe",
    "klist.exe", "wusa.exe", "expand.exe", "makecab.exe", "extrac32.exe",
    "iexpress.exe", "openfiles.exe", "rasdial.exe", "netdom.exe", "ksetup.exe",
    "chcp", "chkdsk", "cipher", "compact", "convert", "fsutil", "mode", "more",
    "print", "recover", "replace", "subst", "tree", "vol", "where",
    "bcdedit", "bcdedit.exe", "bcdboot", "bootrec", "dism", "dism.exe",
    "sfc", "wbadmin", "wbadmin.exe", "wusa", "certreq.exe", "certutil.exe ",
    "tasklist.exe", "taskmgr", "taskmgr.exe", "wmic.exe ", "mspaint",
    "cleanmgr.exe", "charmap.exe", "control.exe", "msinfo32.exe", "dxdiag.exe",
}
_BARE_TOOL = re.compile(r"^[a-z0-9_.\\/-]+\.(exe|dll|com|bat|cmd|ps1|vbs|js|hta)$")


def _unescape_text(s):
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "x" and i + 3 < len(s):
                try:
                    out.append(chr(int(s[i + 2:i + 4], 16))); i += 4; continue
                except ValueError:
                    pass
            out.append({"n": "\n", "r": "\r", "t": "\t", "\\": "\\", '"': '"', "'": "'"}.get(n, n))
            i += 2; continue
        out.append(c); i += 1
    return "".join(out)


def _hex_to_regex(body):
    toks = body.replace("{", " ").replace("}", " ").split()
    rx = []
    for t in toks:
        if t.startswith("[") and t.endswith("]"):
            inner = t[1:-1]
            if "-" in inner:
                a, b = inner.split("-"); rx.append(rb".{%d,%d}" % (int(a), int(b)))
            else:
                rx.append(rb".{%d}" % int(inner))
        elif t in ("??", "?"):
            rx.append(rb".")
        else:
            try:
                rx.append(re.escape(bytes([int(t, 16)])))
            except ValueError:
                rx.append(re.escape(t.encode()))
    return re.compile(b"".join(rx), re.S)


class Rule:
    __slots__ = ("file", "name", "detection_name", "threshold", "strings", "condition")

    def __init__(self, file, name, detection_name, threshold, strings, condition):
        self.file = file
        self.name = name
        self.detection_name = detection_name
        self.threshold = threshold
        self.strings = strings      # list of (sname, kind, payload, weight)
        self.condition = condition  # raw condition text


def _parse_rule(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    m = _RULE_THRESH.search(text); threshold = int(m.group(1)) if m else 1
    m = _RULE_META.search(text); det = m.group(1) if m else os.path.basename(path)
    m = _RULE_NAME.search(text); name = m.group(1) if m else os.path.basename(path)

    strings = []
    for line in text.splitlines():
        lm = _RULE_STR.match(line)
        if not lm:
            continue
        sname, pat, wtxt = lm.group(1), lm.group(2).strip(), lm.group(3)
        weight = int(wtxt)
        if pat.startswith("{"):
            strings.append((sname, "hex", _hex_to_regex(pat), weight))
        elif pat.startswith('"'):
            end = pat.rfind('"')
            lit = _unescape_text(pat[1:end]) if end > 0 else pat.strip('"')
            flags = pat[end + 1:].lower()
            strings.append((sname, "text", (lit, "nocase" in flags), weight))

    cm = _RULE_COND.search(text)
    cond = cm.group(1) if cm else ""
    cond = cond.split("}")[0]
    return Rule(os.path.basename(path), name, det, threshold, strings, cond)


_RULES = None


def load_rules(directory=DEFAULT_RULES_DIR):
    global _RULES
    if _RULES is None:
        _RULES = []
        for fn in sorted(os.listdir(directory)):
            if fn.lower().endswith(".yara"):
                try:
                    _RULES.append(_parse_rule(os.path.join(directory, fn)))
                except Exception:
                    pass
    return _RULES


# condition evaluator

def _glob(pat, name):
    return name.startswith(pat[:-1]) if pat.endswith("*") else name == pat


def _tokenize_cond(c):
    return c.replace("(", " ( ").replace(")", " ) ").split()


def _eval_condition(cond, rule_names, matched_names):
    toks = _tokenize_cond(cond)
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def nxt():
        t = toks[pos[0]]; pos[0] += 1; return t

    def parse_or():
        v = parse_and()
        while peek() == "or":
            nxt(); v = parse_and() or v
        return v

    def parse_and():
        v = parse_not()
        while peek() == "and":
            nxt(); v = parse_not() and v
        return v

    def parse_not():
        if peek() == "not":
            nxt(); return not parse_not()
        return parse_atom()

    def parse_atom():
        t = peek()
        if t == "(":
            nxt(); v = parse_or()
            if peek() == ")":
                nxt()
            return v
        if t == "filesize":
            nxt()
            while peek() not in (None, ")", "and", "or", "not"):
                nxt()
            return True                     # a command line is < 20MB
        if t in ("all", "any") or (t and t.isdigit()):
            return parse_of()
        if t is not None:
            nxt()
        return False

    def parse_of():
        t = nxt()
        need = None if t == "all" else (1 if t == "any" else int(t))
        if peek() == "of":
            nxt()
        if peek() == "(":
            nxt()
        settok = nxt() if peek() else ""
        if peek() == ")":
            nxt()
        pat = settok.lstrip("$")
        total = [n for n in rule_names if _glob(pat, n)]
        matched = [n for n in total if n in matched_names]
        if need is None:
            return len(matched) == len(total) and len(total) > 0
        return len(matched) >= need

    try:
        return parse_or()
    except Exception:
        return None  # parse failure -> caller falls back


def _match(rule, text, wide_bytes):
    matched_names, details, score = set(), [], 0
    for sname, kind, payload, weight in rule.strings:
        if kind == "text":
            lit, nocase = payload
            if not lit:
                continue
            hay = text if nocase else text.lower()
            needle = lit if nocase else lit.lower()
            if needle in hay:
                score += weight; matched_names.add(sname); details.append((lit[:40], weight))
        else:
            if payload.search(wide_bytes):
                score += weight; matched_names.add(sname); details.append(("<hex>", weight))
    return matched_names, details, score


def _is_specific(s):
    if s == "<hex>":
        return True
    t = s.strip().lower()
    if t in GENERIC:
        return False
    if _BARE_TOOL.match(t):
        return False
    return len(t) >= 2


def _fires(rule, text, wide_bytes):
    matched_names, details, score = _match(rule, text, wide_bytes)
    if not matched_names:
        return False, details, score
    val = _eval_condition(rule.condition, [s[0] for s in rule.strings], matched_names)
    if val is None:
        val = score >= rule.threshold       # fallback if condition unparsable
    if not val:
        return False, details, score
    if not any(_is_specific(s) for s, _ in details):
        return False, details, score        # specificity gate
    return True, details, score


def scan(text, directory=DEFAULT_RULES_DIR):
    findings = []
    wide = text.encode("utf-16-le", errors="ignore")
    for rule in load_rules(directory):
        fires, details, score = _fires(rule, text, wide)
        if fires:
            hits = ", ".join(f"{s}({w})" for s, w in details[:6])
            findings.append(("yara", f"{rule.detection_name} [{rule.name}] :: {hits}"))
    return findings


def scan_detailed(text, directory=DEFAULT_RULES_DIR):
    out = []
    wide = text.encode("utf-16-le", errors="ignore")
    for rule in load_rules(directory):
        matched_names, details, score = _match(rule, text, wide)
        if details:
            fires, _, _ = _fires(rule, text, wide)
            out.append((rule, score, details, fires))
    out.sort(key=lambda x: (-int(x[3]), -x[1]))
    return out


def main():
    try:
        text = input("command line / string> ").strip()
    except (EOFError, KeyboardInterrupt):
        print(); return 1
    if not text:
        print("no input"); return 1

    rules = load_rules()
    print(f"\n== CMDHSTR condition scan ({len(rules)} rules) ==")
    rows = scan_detailed(text)
    hits = [r for r in rows if r[3]]
    for rule, score, matched, ok in hits[:40]:
        print(f"  MATCH {rule.detection_name}  ({rule.name})")
        for s, w in matched[:8]:
            print(f"        + {s}  (weight {w})")
    if not hits:
        for rule, score, matched, ok in [r for r in rows if r[1] > 0][:10]:
            print(f"  partial {rule.detection_name}  (below condition)")
    print(f"\nVERDICT: {'FLAGGED' if hits else 'CLEAN'}  ({len(hits)} rule(s) matched)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
