#!/usr/bin/env python3
"""
Re-check coverage against a *running* Metasploit, not its metadata snapshot.

The offline answer comes from a file that ships with the framework, which can
drift from what is installed. This asks the running framework directly, and
confirms every match against the module's own reference list -- because
Metasploit's `cve:` filter matches substrings, so `cve:2022-2069` also returns
the module for CVE-2022-20699.

Start the daemon first (in WSL or on a Linux host):

    msfrpcd -P <password> -S -a 127.0.0.1 -p 55553

then

    MSF_RPC_PASSWORD=<password> python run/verify_live.py
"""
import argparse
import csv
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from iomt_exploit import metasploit

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(HERE, "results", "msf_live_recheck.json")


def connect(host, port, password, ssl):
    try:
        from pymetasploit3.msfrpc import MsfRpcClient
    except ImportError:
        sys.exit("pip install pymetasploit3 first")
    return MsfRpcClient(password, server=host, port=port, ssl=ssl)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=os.environ.get("MSF_RPC_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("MSF_RPC_PORT", 55553)))
    ap.add_argument("--password", default=os.environ.get("MSF_RPC_PASSWORD", ""))
    ap.add_argument("--ssl", action="store_true",
                    default=os.environ.get("MSF_RPC_SSL", "false").lower() == "true")
    args = ap.parse_args()
    if not args.password:
        sys.exit("set MSF_RPC_PASSWORD (or pass --password)")

    client = connect(args.host, args.port, args.password, args.ssl)
    print(f"connected to Metasploit {client.core.version['version']}")

    ground_truth = sorted({c.upper() for c in json.load(
        open(os.path.join(HERE, "results", "cisa_icsma_cves.json"), encoding="utf-8"))})
    valid = sorted({r["cve_id"].upper() for r in csv.DictReader(
        open(os.path.join(HERE, "results", "medical_valid_cves.csv"), encoding="utf-8"))})

    ref_cache: dict = {}
    results = {}
    for label, ids in (("cisa_curated", ground_truth), ("medical_valid", valid)):
        covered = {}
        for i, cve in enumerate(ids, 1):
            modules = metasploit.live_modules_for(client, cve, ref_cache)
            if modules:
                covered[cve] = modules
            if i % 200 == 0:
                print(f"  {label}: {i}/{len(ids)}")
        results[label] = {
            "cves": len(ids),
            "with_module": len(covered),
            "coverage_pct": round(100 * len(covered) / len(ids), 1) if ids else 0.0,
            "covered": covered,
        }
        print(f"{label:14s} {len(covered):4d} of {len(ids):4d} "
              f"({results[label]['coverage_pct']}%)")

    results["msf_version"] = client.core.version["version"]
    json.dump(results, open(OUT, "w", encoding="utf-8"), indent=1)
    print(f"\n-> {os.path.relpath(OUT, HERE)}")


if __name__ == "__main__":
    main()
