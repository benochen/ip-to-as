#!/usr/bin/env python3
"""
ip_to_as_enriched.py

Exemples :
  # Depuis un fichier (une IP par ligne) -> CSV
  python ip_to_as_enriched.py -i ips.txt -o out.csv

  # IPs en ligne de commande -> JSON
  python ip_to_as_enriched.py 8.8.8.8 1.1.1.1 --json

  # Enrichir avec RDAP (CIDR, RIR, holder)
  python ip_to_as_enriched.py -i ips.txt --rdap

Notes :
 - Fournisseur principal : http://ip-api.com (gratuit, limites de débit).
 - Option --rdap interroge https://rdap.org/ip/{ip} (redirigé vers le bon RIR).
 - Pour des volumes massifs, pense à un service payant (ipinfo, MaxMind, etc.).
"""

import argparse
import concurrent.futures
import csv
import json
import re
import sys
import time
from typing import Dict, List, Optional, Tuple

import requests

# ========= Réglages par défaut =========
IPAPI_URL = "http://ip-api.com/json/{ip}"
IPAPI_FIELDS = "status,message,query,as,org,country,countryCode,isp"
RDAP_URL = "https://rdap.org/ip/{ip}"

DEFAULT_TIMEOUT = 6.0
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF_BASE = 0.8  # secondes
DEFAULT_WORKERS = 12
DEFAULT_QPS = 9  # garde une marge sous les limites publiques

AS_RE = re.compile(r"AS\s*(\d+)\s*(.*)", re.IGNORECASE)


def backoff_sleep(attempt: int, base: float) -> None:
    time.sleep(base * (2 ** (attempt - 1)))


def parse_as(as_field: Optional[str], org_field: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Extrait (asn, org_name) depuis un champ 'AS15169 Google LLC' + org fallback."""
    if not as_field and not org_field:
        return None, None
    if as_field:
        m = AS_RE.match(as_field)
        if m:
            asn = m.group(1)
            name = m.group(2).strip() or org_field
            return asn, name
        digits = "".join(ch for ch in as_field if ch.isdigit())
        name = as_field.replace("AS" + digits, "").strip() if digits else None
        return (digits or None), (name or org_field)
    return None, org_field


def http_get_json(url: str, params: Optional[dict] = None, timeout: float = DEFAULT_TIMEOUT,
                  retries: int = DEFAULT_RETRIES, backoff_base: float = DEFAULT_BACKOFF_BASE) -> Optional[dict]:
    for attempt in range(1, retries + 1):
        try:
            r = requests.get(url, params=params, timeout=timeout)
            if r.status_code == 429:
                backoff_sleep(attempt, backoff_base)
                continue
            r.raise_for_status()
            return r.json()
        except (requests.Timeout, requests.ConnectionError):
            if attempt == retries:
                return None
            backoff_sleep(attempt, backoff_base)
        except Exception:
            return None
    return None


def query_ipapi(ip: str) -> Dict:
    j = http_get_json(IPAPI_URL.format(ip=ip), params={"fields": IPAPI_FIELDS})
    if not j:
        return {"source_ipapi": False, "ip": ip, "error_ipapi": "no_response"}
    if j.get("status") != "success":
        return {"source_ipapi": False, "ip": ip, "error_ipapi": j.get("message", "api_error"), "raw_ipapi": j}
    asn, org_name = parse_as(j.get("as"), j.get("org"))
    return {
        "source_ipapi": True,
        "ip": ip,
        "asn": asn,
        "org_name": org_name,
        "country": j.get("country"),
        "country_code": j.get("countryCode"),
        "isp": j.get("isp"),
        "raw_ipapi": j,
    }


def query_rdap(ip: str) -> Dict:
    j = http_get_json(RDAP_URL.format(ip=ip))
    if not j:
        return {"source_rdap": False, "error_rdap": "no_response"}
    # network info
    net = j.get("network") or {}
    cidr = net.get("cidr") or net.get("startAddress")
    name = net.get("name")
    # RIR heuristique : handle dans "port43" (ex: whois.arin.net) ou notices
    rir = None
    port43 = j.get("port43")
    if isinstance(port43, str) and "whois." in port43:
        rir = port43.split("whois.", 1)[-1].split(".", 1)[0].upper()

    # Titulaire (holder) : on tente entity vcardArray "fn"
    holder = None
    entities = j.get("entities") or []
    for e in entities:
        v = e.get("vcardArray")
        if isinstance(v, list) and len(v) == 2 and isinstance(v[1], list):
            for item in v[1]:
                if isinstance(item, list) and len(item) >= 3 and item[0] == "fn":
                    holder = item[3]
                    break
        if holder:
            break

    return {
        "source_rdap": True,
        "cidr": cidr,
        "rir": rir,
        "holder": holder or name,
        "raw_rdap": j,
    }


def process_ip(ip: str, use_rdap: bool, qps_delay: float) -> Dict:
    # Throttle “pauvre mais sympa”
    if qps_delay > 0:
        time.sleep(qps_delay)
    res = {"ip": ip, "ok": False, "error": None, "source": []}

    ipapi = query_ipapi(ip)
    if ipapi.get("source_ipapi"):
        res.update({
            "asn": ipapi.get("asn"),
            "org_name": ipapi.get("org_name"),
            "country": ipapi.get("country"),
            "country_code": ipapi.get("country_code"),
            "isp": ipapi.get("isp"),
        })
        res["source"].append("ip-api")
    else:
        res["error"] = ipapi.get("error_ipapi", "unknown")

    if use_rdap:
        rd = query_rdap(ip)
        if rd.get("source_rdap"):
            res.update({
                "cidr": rd.get("cidr"),
                "rir": rd.get("rir"),
                "holder": rd.get("holder"),
            })
            res["source"].append("rdap")
        else:
            # ne remplace pas l'erreur principale si ip-api a réussi
            if not res.get("asn"):
                res["error"] = (res.get("error") or "") + "|rdap:" + rd.get("error_rdap", "unknown")

    # Statut final
    res["ok"] = bool(res.get("asn"))
    if not res["ok"] and not res.get("error"):
        res["error"] = "asn_missing"
    return res


def load_ips(path: str) -> List[str]:
    ips = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip().split("#", 1)[0].strip()
            if line:
                ips.append(line)
    # dédup ordre préservé
    seen, out = set(), []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def main():
    p = argparse.ArgumentParser(description="Résolution IP -> ASN + org, enrichie (RDAP).")
    p.add_argument("ips", nargs="*", help="Adresses IP si pas de --input")
    p.add_argument("-i", "--input", help="Fichier avec une IP par ligne")
    p.add_argument("-o", "--output", help="Fichier de sortie (CSV par défaut).")
    p.add_argument("--json", action="store_true", help="Sortie JSON (au lieu de CSV).")
    p.add_argument("--rdap", action="store_true", help="Activer l’enrichissement RDAP (CIDR, RIR, holder).")
    p.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS, help="Threads concurrents.")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Timeout HTTP.")
    p.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="Retries HTTP.")
    p.add_argument("--qps", type=float, default=DEFAULT_QPS, help="Requêtes max par seconde (approx).")
    args = p.parse_args()



    ips: List[str] = []
    if args.input:
        ips.extend(load_ips(args.input))
    if args.ips:
        # dédup simple en bout
        for ip in args.ips:
            if ip not in ips:
                ips.append(ip)

    if not ips:
        print("Aucune IP fournie. Utilise --input fichier.txt ou passe des IP en arguments.", file=sys.stderr)
        sys.exit(2)

    # Throttle : délai moyen entre jobs par worker pour rester ≈ qps
    # (approximatif mais suffisant)
    qps_delay = 0.0
    if args.qps and args.qps > 0:
        qps_delay = max(0.0, (args.workers / args.qps) * 0.9)

    results: List[Dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(process_ip, ip, args.rdap, qps_delay) for ip in ips]
        for fut in concurrent.futures.as_completed(futs):
            results.append(fut.result())

    # tri par IP pour une sortie stable
    results.sort(key=lambda r: r["ip"])

    if args.json:
        text = json.dumps(results, ensure_ascii=False, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(text)
        else:
            print(text)
        return

    # CSV par défaut
    fieldnames = ["ip", "ok", "asn", "org_name", "holder", "cidr", "rir", "country", "country_code", "isp", "source", "error"]
    if args.output:
        out = open(args.output, "w", newline="", encoding="utf-8")
    else:
        out = sys.stdout

    w = csv.DictWriter(out, fieldnames=fieldnames)
    w.writeheader()
    for r in results:
        row = {k: r.get(k) for k in fieldnames}
        # source sous forme "ip-api|rdap"
        if isinstance(row.get("source"), list):
            row["source"] = "|".join(row["source"])
        w.writerow(row)

    if args.output and out is not sys.stdout:
        out.close()


if __name__ == "__main__":
    main()
