#!/usr/bin/env python3
import re
import sys

from dfcore import normalize_cmdline
from scan_cmdline import analyze
import scan_amsi
import scan_amsiuac
import scan_clickfix
import scan_cmdshell
import scan_defender_tamper
import scan_download
import scan_embedded
import scan_lolbin
import scan_obfusc
import scan_paste
import scan_ps_ast
import scan_ps_deep
import scan_persist_cmd
import scan_ai
import scan_runmru
import scan_rpf
import scan_wmi
import scan_wsh
import scan_yara
from scan_obfusc import shannon_entropy, looks_like_base64


def gather(cmd, elevated):
    findings = []

    variants, notes, tags = normalize_cmdline(cmd)
    _, _, _, hits, cflag, score = analyze(cmd)
    for h in hits:
        findings.append(("scan", h["detector"], h["why"]))

    for d, w in scan_yara.scan(cmd + "\n" + variants["resolved"]):
        findings.append(("yara", "sig", w))

    # --- LOLBin matrix ---
    bname, args, lol_hits = scan_lolbin.analyze_lolbin(cmd)
    for h in lol_hits:
        findings.append(("lolbin", "sig", h))

    # --- PowerShell deep ---
    ps_hits, ps_obf = scan_ps_deep.analyze_ps(cmd)
    for h in ps_hits:
        findings.append(("ps_deep", "amsi", h))

    # --- RPF fileless/JIT ---
    _, rpf_hits = scan_rpf.analyze_rpf(cmd)
    for h in rpf_hits:
        findings.append(("rpf", "rpf", h))

    # --- WMI/DCOM ---
    for h in scan_wmi.analyze_wmi(cmd):
        findings.append(("wmi", "behavior", h))

    # --- cmd shell chaining ---
    for d, w in scan_cmdshell.analyze_cmdshell(cmd):
        findings.append(("cmdshell", d, w))

    # --- embedded script layers ---
    layers = scan_embedded.extract_layers(cmd)
    for name, body in layers:
        _, _, _, lhits, lflag, _ = analyze(body)
        for h in lhits:
            findings.append((f"embedded:{name}", h["detector"], h["why"]))

    amsi_body = cmd + "\n" + "\n".join(b for _, b in layers)
    for h in scan_amsi.analyze_amsi(amsi_body):
        findings.append(("amsi", "amsi", h))

    # --- download-and-execute cradle ---
    for d, w in scan_download.analyze_download(cmd):
        findings.append(("download", d, w))

    # --- persistence-creation commands ---
    for d, w in scan_persist_cmd.analyze_persist(cmd):
        findings.append(("persist", d, w))

    # --- security-software tamper ---
    for d, w in scan_defender_tamper.analyze_tamper(cmd):
        findings.append(("tamper", d, w))

    layer_text = "\n".join(b for _, b in layers)
    for d, w in scan_wsh.analyze_wsh(layer_text):
        findings.append(("wsh", d, w))

    # --- decoded PowerShell AST walk ---
    for how, body in scan_ps_ast.decode_payloads(cmd):
        for d, w in scan_ps_ast.analyze_ast(body):
            findings.append(("ps_ast", d, w))

    # --- paste-borne obfuscation ---
    for d, w in scan_paste.analyze_paste(cmd):
        findings.append(("paste", d, w))

    # --- real Defender neural net (BMClientV1), pure numpy ---
    for d, w in scan_ai.analyze_ai(cmd):
        findings.append(("ai", "ml", w))

    # --- RunMRU / clipboard (the paste itself) ---
    for d, w in scan_runmru.analyze_clipboard(cmd, "Win+R paste"):
        findings.append(("clipboard", d, w))

    cf_score, cf_labels = scan_clickfix.analyze_clickfix(cmd)
    if cf_score >= 6:
        for l in cf_labels:
            findings.append(("clickfix", "ml", f"fingerprint: {l}"))

    # --- AMSI-UAC (elevated Run) ---
    if elevated or re.search(r"runas|verb\s+runas|-verb\s+runas", cmd, re.I):
        for w in scan_amsiuac.scan_exe(cmd):
            findings.append(("amsiuac", "amsiuac", w))

    return variants, notes, tags, findings, score


def main(argv):
    elevated = "--elevated" in argv
    try:
        cmd = input("Win+R command line> ").strip()
    except (EOFError, KeyboardInterrupt):
        print(); return 1
    if not cmd:
        print("no input"); return 1

    variants, notes, tags, findings, score = gather(cmd, elevated)
    cf_score, _ = scan_clickfix.analyze_clickfix(cmd)

    # dedupe
    seen, uniq = set(), []
    for s, d, w in findings:
        if (s, d, w) not in seen:
            seen.add((s, d, w)); uniq.append((s, d, w))

    print("\n================ Win+R / ClickFix run-1 scan ================")
    print(f"  input     : {cmd[:160]}")
    print(f"  tags      : {' '.join(tags) if tags else '-'}")
    print(f"  deobf     : {', '.join(notes) if notes else '-'}")
    print(f"  resolved  : {variants['resolved'][:160]}")
    print(f"  entropy   : {shannon_entropy(cmd):.2f}  b64={looks_like_base64(cmd)}")
    print(f"  clickfix  : score={cf_score}")
    try:
        ai_probs, ai_ev, ai_p1, ai_p2 = scan_ai.score_cmdline(cmd)
        print(f"  ai (model): class0={ai_probs[0]:.4f}  class1={ai_probs[1]:.4f}"
              f"   [BMClientV1; feats ev={ai_ev!r} p1={ai_p1[:40]!r} p2={ai_p2[:40]!r}]")
    except Exception as e:
        print(f"  ai (model): error {e}")

    if uniq:
        print("\n  -- detections --")
        for s, d, w in uniq:
            print(f"    [{s:18}] {w}")

    print("\n============================================================")
    if uniq:
        # prefer a real VDM signature name when one fired
        real = next((w.split(" [")[0] for s, d, w in uniq if s == "yara"), None)
        if real:
            name = real
        else:
            dets = {d for _, d, _ in uniq}
            name = "Trojan:Win32/Commando.A!ml" if "ml" in dets else \
                   "Trojan:Win32/ClickFix.CCA!MTB" if "behavior" in dets else \
                   "Trojan:PowerShell/<family>" if "amsi" in dets else \
                   f"Trojan:Win32/{uniq[0][2].split()[0] if uniq else 'Suspicious'}"
        print("  VERDICT: FLAGGED")
        print(f"  likely  : {name}")
    elif cf_score >= 5 or score >= 3:
        print("  VERDICT: SUSPICIOUS (threshold-adjacent)")
    else:
        print("  VERDICT: CLEAN")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
