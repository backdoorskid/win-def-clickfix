#!/usr/bin/env python3
import sys
import unicodedata

INVISIBLE = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE (BOM)",
    "\u00ad": "SOFT HYPHEN",
    "\u180e": "MONGOLIAN VOWEL SEPARATOR",
    "\u00a0": "NO-BREAK SPACE",
    "\u034f": "COMBINING GRAPHEME JOINER",
}
BIDI = {c: "BIDI CONTROL" for c in
        "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f"}

HOMOGLYPH = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u04bb": "h", "\u0456": "i", "\u0501": "d",
    "\u03b1": "a", "\u03bf": "o", "\u03c1": "p", "\u03c5": "u",
}


def analyze_paste(text):
    hits = []
    inv = [f"{INVISIBLE[ch]} (U+{ord(ch):04X})" for ch in text if ch in INVISIBLE]
    bid = [f"{BIDI[ch]} (U+{ord(ch):04X})" for ch in text if ch in BIDI]
    if inv:
        hits.append(("paste", f"invisible/zero-width characters: {', '.join(sorted(set(inv)))}"))
    if bid:
        hits.append(("paste", f"bidi control characters: {', '.join(sorted(set(bid)))}"))

    ascii_cmds = any(w in text.lower() for w in
                     ("powershell", "pwsh", "cmd", "mshta", "rundll32", "iex", "curl"))
    homo = [ch for ch in text if ch in HOMOGLYPH]
    if homo and (ascii_cmds or len(homo) >= 3):
        hits.append(("paste", f"{len(homo)} homoglyph character(s) mixed with ASCII command"))

    if text != text.strip() or "\r" in text or "\n" in text:
        hits.append(("paste", "leading/trailing whitespace or embedded newline (multi-line paste)"))

    wide = [ch for ch in text if unicodedata.east_asian_width(ch) == "F" and ch.isalnum()]
    if wide:
        hits.append(("paste", f"{len(wide)} fullwidth character(s)"))

    if "%25" in text or "&#x" in text.lower():
        hits.append(("paste", "double/entity encoded characters"))
    return hits


def main():
    try:
        s = input("pasted (Win+R) text> ")
    except (EOFError, KeyboardInterrupt):
        print(); return 1
    hits = analyze_paste(s)
    print("\n== paste-borne scan ==")
    if hits:
        print("VERDICT: FLAGGED")
        print("  detection : Trojan:Win32/ClickFix (paste obfuscation)")
        for d, w in hits:
            print(f"    - {w}")
    else:
        print("VERDICT: CLEAN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
