#!/usr/bin/env python3
"""Evalua los informes JSON contra gates.json. Sale con 1 si falla un gate bloqueante."""
import json, os, sys
from collections import Counter

reports, cfg = sys.argv[1], sys.argv[2]
enforce = os.environ.get("ENFORCE", "true").lower() == "true"

def load(name):
    p = os.path.join(reports, name)
    if not os.path.exists(p):
        return None
    with open(p) as f:
        return json.load(f)

def trivy(name, key):
    c, d = Counter(), load(name)
    if d is None: return None
    for r in d.get("Results", []):
        for v in r.get(key) or []:
            c[v.get("Severity", "UNKNOWN").lower()] += 1
    return c

def semgrep():
    d = load("semgrep.json")
    if d is None: return None
    m = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    return Counter(m.get(r["extra"]["severity"], "low") for r in d.get("results", []))

def zap():
    d = load("zap.json")
    if d is None: return None
    m = {"3": "high", "2": "medium", "1": "low", "0": "info"}
    c = Counter()
    for s in d.get("site", []):
        for a in s.get("alerts", []):
            c[m.get(str(a.get("riskcode")), "info")] += 1
    return c

counts = {
    "trivy-sca": trivy("trivy-sca.json", "Vulnerabilities"),
    "trivy-iac": trivy("trivy-iac.json", "Misconfigurations"),
    "semgrep": semgrep(),
    "zap": zap(),
}
failed = False
print(f"{'GATE':32} {'ENCONTRADOS':>11} {'MAX':>4} {'MODO':>6} RESULTADO")
for g in json.load(open(cfg))["gates"]:
    c = counts[g["tool"]]
    if c is None:
        print(f"{g['name']:32} {'sin informe':>11} {g['max']:>4} {g['mode']:>6} AVISO (informe ausente)")
        continue
    n = c.get(g["severity"], 0)
    exceeded = n > g["max"]
    blocking = exceeded and g["mode"] == "block" and enforce
    res = "FALLA (bloquea)" if blocking else ("SUPERA (aviso)" if exceeded else "OK")
    print(f"{g['name']:32} {n:>11} {g['max']:>4} {g['mode']:>6} {res}")
    failed |= blocking
sys.exit(1 if failed else 0)
