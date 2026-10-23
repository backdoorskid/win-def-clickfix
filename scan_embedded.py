#!/usr/bin/env python3
import base64
import re
import sys
import zlib

from dfcore import normalize_cmdline, decode_b64_powershell
from scan_cmdline import analyze

INLINE = [
    re.compile(r"-command\s+(?:\(\s*)?[\"'](.+?)[\"']", re.I | re.S),
    re.compile(r"-c\s+[\"'](.+?)[\"']", re.I | re.S),
    re.compile(r"(javascript:|vbscript:)(.+)$", re.I | re.S),
    re.compile(r"mshta\s+[\"']?(.+?\.(?:hta|js|vbs))", re.I),
]


def try_zlib(b: bytes):
    for wbits in (15, -15, 31):
        try:
            return zlib.decompress(b, wbits).decode("utf-8", "ignore")
        except Exception:
            continue
    return None


def extract_layers(cmd, depth=0, seen=None):
    if seen is None:
        seen = set()
    layers = []
    if depth > 4 or cmd in seen:
        return layers
    seen.add(cmd)

    # base64 -enc
    for txt, how in decode_b64_powershell(cmd):
        layers.append((f"b64-layer#{depth}", txt))
        layers += extract_layers(txt, depth + 1, seen)

    # inline quoted bodies
    for rx in INLINE:
        for m in rx.finditer(cmd):
            body = m.group(m.lastindex or 1)
            if body and body not in seen:
                layers.append((f"inline#{depth}", body))
                layers += extract_layers(body, depth + 1, seen)

    # zlib blobs (base64 -> zlib)
    for m in re.finditer(r"[A-Za-z0-9+/]{40,}={0,2}", cmd):
        try:
            raw = base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4))
            z = try_zlib(raw)
            if z:
                layers.append((f"zlib#{depth}", z))
                layers += extract_layers(z, depth + 1, seen)
        except Exception:
            pass
    return layers


def main():
    try:
        cmd = input("command line> ").strip()
    except (EOFError, KeyboardInterrupt):
        print(); return 1
    if not cmd:
        print("no input"); return 1

    layers = extract_layers(cmd)
    print("\n== embedded script layers ==")
    print(f"  layer 0: {cmd[:200]}")
    for name, body in layers[:12]:
        print(f"  {name}: {body[:200]}")

    all_hits = []
    for name, body in [("root", cmd)] + layers:
        _, _, _, hits, cflag, _ = analyze(body)
        if cflag:
            all_hits.append((name, hits[0]))

    if all_hits:
        print("\nVERDICT: FLAGGED")
        for name, h in all_hits:
            print(f"  [{name}/{h['detector']}] {h['why']}")
    elif layers:
        print("\nVERDICT: SUSPICIOUS (embedded layers present, no rule matched)")
    else:
        print("\nVERDICT: CLEAN (no embedded script)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
