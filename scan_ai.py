#!/usr/bin/env python3
import os
import re
import struct
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL = os.path.join(HERE, "models", "BMCLIENTV1_2026-07-20.onnx")
TOK = re.compile(r"[a-zA-Z0-9_]+")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL = re.compile(r"https?://([^/\s\"']+)", re.I)
PORT = re.compile(r":(\d{2,5})\b")

DECISION_THRESHOLD = 0.5   # class-1 probability above which we report


def _vi(b, i):
    s = 0; v = 0
    while True:
        c = b[i]; i += 1
        v |= (c & 0x7F) << s
        if not (c & 0x80):
            break
        s += 7
    return v, i


def _parse(b):
    fs = []; i = 0; n = len(b)
    while i < n:
        tag, i = _vi(b, i)
        fn, wt = tag >> 3, tag & 7
        if wt == 0:
            v, i = _vi(b, i); fs.append((fn, 0, v))
        elif wt == 2:
            ln, i = _vi(b, i); fs.append((fn, 2, b[i:i + ln])); i += ln
        elif wt == 5:
            fs.append((fn, 5, b[i:i + 4])); i += 4
        elif wt == 1:
            fs.append((fn, 1, b[i:i + 8])); i += 8
        else:
            raise ValueError(wt)
    return fs


def _one(fs, fn, d=None):
    for f, w, v in fs:
        if f == fn:
            return v
    return d


def _all(fs, fn):
    return [v for f, w, v in fs if f == fn]


def _s(b):
    return b.decode("utf-8", "ignore") if isinstance(b, bytes) else b


def _packed(bb):
    out = []; j = 0
    while j < len(bb):
        v, j = _vi(bb, j); out.append(v)
    return out


class _Model:
    def __init__(self, path):
        data = open(path, "rb").read()
        M = _parse(data)
        G = _parse(_one(M, 7))
        self.nodes = [_parse(x) for x in _all(G, 1)]
        self.graph = G

        def node_attr_strings(name):
            for nd in self.nodes:
                if _s(_one(nd, 3, b"")) == name:
                    for a in _all(nd, 5):
                        af = _parse(a)
                        if _s(_one(af, 1, b"")) == "pool_strings":
                            return [_s(x) for x in _all(af, 9)]
            return []

        self.pool1 = node_attr_strings("f_TfIdfVectorizer")
        self.pool2 = node_attr_strings("f_TfIdfVectorizer1")

        self.le_keys, self.le_vals, self.le_default = [], [], -1
        for nd in self.nodes:
            if _s(_one(nd, 4, b"")) == "LabelEncoder":
                for a in _all(nd, 5):
                    af = _parse(a); nm = _s(_one(af, 1, b""))
                    if nm == "keys_strings":
                        self.le_keys = [_s(x) for x in _all(af, 9)]
                    elif nm == "values_int64s":
                        self.le_vals = _all(af, 8)
                    elif nm == "default_int64":
                        d = _one(af, 3)
                        self.le_default = d - (1 << 64) if d >= (1 << 63) else d

        self.W = self._t("onnx::GRU_95", np.float32)[0]     # [192,101]
        self.R = self._t("onnx::GRU_96", np.float32)[0]     # [192,64]
        self.B = self._t("onnx::GRU_97", np.float32)[0]     # [384]
        self.WQ = self._t("base_model.fc.weight_quantized", np.int8)      # [64,2]
        self.WSCALE = float(self._t("base_model.fc.weight_scale", np.float32)[0])
        self.WZP = int(self._t("base_model.fc.weight_zero_point", np.int8)[0])
        self.BIAS = self._t("base_model.fc.bias", np.float32)            # [2]
        self.IDF1 = self._t("idfcst", np.float32)
        self.IDF2 = self._t("idfcst1", np.float32)

        H = 64
        self.H = H
        self.Wz, self.Wr, self.Wh = self.W[0:H], self.W[H:2*H], self.W[2*H:3*H]
        self.Rz, self.Rr, self.Rh = self.R[0:H], self.R[H:2*H], self.R[2*H:3*H]
        self.Wbz, self.Wbr, self.Wbh = self.B[0:H], self.B[H:2*H], self.B[2*H:3*H]
        self.Rbz, self.Rbr, self.Rbh = self.B[3*H:4*H], self.B[4*H:5*H], self.B[5*H:6*H]

    def _t(self, name, dt):
        for x in _all(self.graph, 5):
            t = _parse(x)
            if _s(_one(t, 8, b"")) != name:
                continue
            dims = _all(t, 1)
            raw = _one(t, 9)
            if raw is not None:
                arr = np.frombuffer(raw, dtype=dt)
            else:
                fdat, i32 = [], []
                for f, w, v in t:
                    if f == 4:
                        fdat += list(struct.unpack("<f", v)) if w == 5 else list(struct.unpack("<%df" % (len(v)//4), v))
                    elif f == 5:
                        i32 += ([v] if w == 0 else _packed(v))
                arr = np.array(fdat or i32, dtype=np.float32 if fdat else np.int32)
            return arr.reshape(dims) if dims else arr
        raise KeyError(name)


_M = None


def _model():
    global _M
    if _M is None:
        _M = _Model(MODEL)
    return _M


def _sigmoid(x):
    return 1.0 / (1.0 + np.exp(-x))


def _tfidf(text, pool, idf):
    toks = TOK.findall(text.lower())
    idx = {t: j for j, t in enumerate(pool)}
    v = np.zeros(len(pool), dtype=np.float32)
    for t in toks:
        j = idx.get(t)
        if j is not None:
            v[j] += 1.0
    v *= idf
    n = np.linalg.norm(v)
    return v / n if n > 0 else v


def score(event_attribute, utf8p1, utf8p2, hidden=None):
    m = _model()
    h = np.zeros(m.H, dtype=np.float32) if hidden is None else np.asarray(hidden, np.float32)
    try:
        ev = float(m.le_vals[m.le_keys.index(str(event_attribute))])
    except (ValueError, IndexError):
        ev = float(m.le_default)
    x = np.concatenate([[ev], _tfidf(utf8p1, m.pool1, m.IDF1),
                        _tfidf(utf8p2, m.pool2, m.IDF2)]).astype(np.float32)
    z = _sigmoid(x @ m.Wz.T + h @ m.Rz.T + m.Wbz + m.Rbz)
    r = _sigmoid(x @ m.Wr.T + h @ m.Rr.T + m.Wbr + m.Rbr)
    hh = np.tanh(x @ m.Wh.T + (r * h) @ m.Rh.T + m.Wbh + m.Rbh)
    h = (1 - z) * hh + z * h
    mn, mx = float(h.min()), float(h.max())
    scale = (mx - mn) / 255.0 if mx > mn else 1.0
    zp = int(np.clip(round(-mn / scale), 0, 255))
    q = np.clip(np.round(h / scale) + zp, 0, 255).astype(np.int32)
    logits = ((q - zp) @ (m.WQ.astype(np.int32) - m.WZP)).astype(np.float32) * (scale * m.WSCALE) + m.BIAS
    p = np.exp(logits - logits.max())
    return p / p.sum(), h


def _derive_features(cmd):
    m = _model()
    ev = m.le_keys[0] if m.le_keys else "16384"        # engine mapping unreversed
    p1 = cmd                                            # file/path tokens come from the string
    feats = []
    for ip in IPV4.findall(cmd):
        feats.append("remoteip=" + ip)
    for host in URL.findall(cmd):
        feats.append("domain=" + host)
    for port in PORT.findall(cmd):
        feats.append("destport=" + port)
    if re.search(r"https://", cmd, re.I):
        feats.append("proto=https")
    elif re.search(r"http://", cmd, re.I):
        feats.append("proto=http")
    return ev, p1, " ".join(feats)


def score_cmdline(cmd):
    ev, p1, p2 = _derive_features(cmd)
    probs, _ = score(ev, p1, p2)
    return probs, ev, p1, p2


def analyze_ai(cmd):
    try:
        ev, p1, p2 = _derive_features(cmd)
        probs, _ = score(ev, p1, p2)
    except Exception as e:
        return [("ai", f"model error: {e}")]
    p1c = float(probs[1])
    if p1c >= DECISION_THRESHOLD:
        return [("ai", f"BMClientV1 model: class1={p1c:.4f} (>= {DECISION_THRESHOLD})")]
    return []


def main():
    print("scan_ai — real Defender BMClientV1 model (numpy)")
    if len(sys.argv) >= 4:
        ev, a, b = sys.argv[1], sys.argv[2], sys.argv[3]
    else:
        ev = input("event_attribute> ").strip() or "16384"
        a = input("utf8p1 (file/path)> ").strip()
        b = input("utf8p2 (net/mem)> ").strip()
    probs, h = score(ev, a, b)
    print(f"output = {probs}  (class0={probs[0]:.4f} class1={probs[1]:.4f})")
    print("VERDICT:", "FLAGGED" if probs[1] >= DECISION_THRESHOLD else "CLEAN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
