#!/usr/bin/env python3
import base64
import binascii
import re
import zlib  # noqa: F401  (kept for callers that introspect availability)

JS_MEMBER_IDIOMS = ("fromcharcode", "charcodeat", "charat", "concat",
                    "substr", "substring", "split", "join", "replace", "tolowercase")

_PAIR_CONCAT = re.compile(r"""(['"])(.*?)\1\s*(\+|&)\s*(['"])(.*?)\4""")


def resolve_concat(s: str, rounds: int = 8) -> str:
    for _ in range(rounds):
        new = _PAIR_CONCAT.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(5)}{m.group(1)}", s)
        if new == s:
            break
        s = new
    return s


_CALLOP_RE = re.compile(r"&\s*\(\s*(['\"])(.*?)\1\s*\)")
_CALLOP_BARE_RE = re.compile(r"&\s*([A-Za-z_][\w.-]*)")


def resolve_call_operator(s: str) -> str:
    s = _CALLOP_RE.sub(lambda m: m.group(2), s)
    s = _CALLOP_BARE_RE.sub(lambda m: m.group(1), s)
    return s


_FROMCHAR_RE = re.compile(r"(?:String\.)?fromchar(?:code)?\s*\(([^)]*)\)", re.I)
_CHARCODE_RE = re.compile(r"(?:String\.)?charcodeat\s*\(([^)]*)\)", re.I)


def resolve_fromcharcode(s: str) -> str:
    def _conv(args: str) -> str:
        out = []
        for tok in re.split(r"[,\s]+", args.strip()):
            if not tok:
                continue
            try:
                out.append(chr(int(tok, 0) & 0xFF))
            except ValueError:
                return ""  # non-constant -> engine tags [EmbeddedEnc] instead
        return "".join(out)
    return _FROMCHAR_RE.sub(lambda m: _conv(m.group(1)) or m.group(0), s)


def resolve_escapes(s: str) -> str:
    def ch(digits, base):
        try:
            return chr(int(digits, base) & 0xFFFF)
        except ValueError:
            return ""
    s = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: ch(m.group(1), 16) or m.group(0), s)
    s = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: ch(m.group(1), 16) or m.group(0), s)
    s = re.sub(r"\\([0-7]{1,3})", lambda m: ch(m.group(1), 8) or m.group(0), s)
    return s


_ENC_FLAG = re.compile(r"(?:-enc|-encodedcommand|-e)\s+([A-Za-z0-9+/=]{8,})", re.I)


def decode_b64_powershell(s: str):
    decoded = []
    for m in _ENC_FLAG.finditer(s):
        blob = m.group(1)
        pad = blob + "=" * (-len(blob) % 4)
        for enc in ("utf-16-le", "utf-8"):
            try:
                raw = base64.b64decode(pad)
                txt = raw.decode(enc, errors="ignore")
                if txt and any(c.isprintable() for c in txt):
                    decoded.append((txt, f"base64(-enc,{enc})"))
                    break
            except (binascii.Error, ValueError):
                continue
    return decoded


def normalize_cmdline(cmd: str):
    notes = []
    low = cmd.lower()
    for idiom in JS_MEMBER_IDIOMS:
        if "." + idiom in low or idiom in low:
            notes.append(f"idiom:{idiom}")

    v = cmd
    v = resolve_concat(v); v = resolve_call_operator(v)
    v = resolve_fromcharcode(v); v = resolve_escapes(v)
    v = v.replace("^", "").replace("`", "")

    decoded = decode_b64_powershell(v)
    for txt, how in decoded:
        notes.append(how)
        v = v + "\n" + txt

    tags = []
    if re.search(r"-enc(odedcommand)?\b|base64", low) or decoded:
        tags.append("[EmbeddedEnc]")
    if re.search(r"-command|-c\b|iex|invoke-expression", low):
        tags.append("[EmbeddedScript]")
    if re.search(r"fromcharcode|charcodeat|\+ *['\"]|\" *\+", low):
        tags.append("[EmbeddedString]")
    if re.search(r"frombase64|decompress|zlib|\bgzip\b", low):
        tags.append("[ZlibDecompress]")

    flat = re.sub(r"[\s\"'`^]+", "", v).lower()
    return {
        "raw": cmd,
        "resolved": v,
        "flat": flat,
        "lower": v.lower(),
    }, notes, tags
