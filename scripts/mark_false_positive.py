#!/usr/bin/env python3
"""Triaje: marca un hallazgo como falso positivo en DefectDojo. Uso: mark_false_positive.py <id> "<motivo>" """
import os, sys, requests
fid, why = sys.argv[1], sys.argv[2]
url, tok = os.environ["DD_URL"], os.environ["DD_TOKEN"]
h = {"Authorization": f"Token {tok}"}
r = requests.patch(f"{url}/api/v2/findings/{fid}/", headers=h,
                   json={"false_p": True, "active": False, "verified": False})
r.raise_for_status()
requests.post(f"{url}/api/v2/findings/{fid}/notes/", headers=h, json={"entry": f"Falso positivo: {why}"})
print("OK", fid)
