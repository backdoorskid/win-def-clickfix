#!/usr/bin/env python3
import math
import re
import sys
from collections import Counter

from dfcore import (resolve_concat, resolve_call_operator, resolve_fromcharcode,
                    resolve_escapes, decode_b64_powershell, normalize_cmdline)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def looks_like_base64(s: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9+/]{20,}={0,2}", s or ""))


def main():
    try:
        s = input("string> ")
    except (EOFError, KeyboardInterrupt):
        print(); return 1
    if not s:
        print("no input"); return 1

    stages = [("input", s),
              ("concat", resolve_concat(s)),
              ("call-op", resolve_call_operator(s)),
              ("fromcharcode", resolve_fromcharcode(s)),
              ("escapes", resolve_escapes(s))]

    print("\n== deobfuscation stages ==")
    for name, val in stages:
        if val != s or name == "input":
            print(f"  {name:12}: {val[:300]}")

    for txt, how in decode_b64_powershell(s):
        print(f"  {how:12}: {txt[:300]}")

    variants, notes, tags = normalize_cmdline(s)
    ent = shannon_entropy(s)
    print("\n== metrics ==")
    print(f"  entropy   : {ent:.2f} bits/char")
    print(f"  length    : {len(s)}")
    print(f"  tags      : {' '.join(tags) if tags else '-'}")
    print(f"  idioms    : {', '.join(notes) if notes else '-'}")
    print(f"  flat      : {variants['flat'][:200]}")

    flag = bool(tags) or ent > 4.5 or looks_like_base64(s) or bool(decode_b64_powershell(s))
    print(f"\nVERDICT: {'OBFUSCATED (would tag as [Embedded*])' if flag else 'PLAIN'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
