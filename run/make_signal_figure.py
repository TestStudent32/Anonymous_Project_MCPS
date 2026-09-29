#!/usr/bin/env python3
"""
Draw where the public exploitation signals agree. Offline.

    python run/make_signal_figure.py
    python run/make_signal_figure.py --epss-threshold 0.1
"""
import argparse
import csv
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from iomt_exploit import figures

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = lambda *p: os.path.join(HERE, *p)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--epss-threshold", type=float, default=0.5,
                    help="EPSS probability at which a CVE counts as flagged")
    args = ap.parse_args()

    signals = json.load(open(R("results", "exploit_signals.json"), encoding="utf-8"))
    rows = list(csv.DictReader(open(R("results", "medical_valid_cves.csv"), encoding="utf-8")))

    modules = {r["cve_id"].upper() for r in rows if r["msf_module_count"] not in ("", "0")}
    kev = set(signals["kev"]["valid"]["cves"])
    epss = {c for c, v in signals["epss"]["scores_valid"].items()
            if float(v) >= args.epss_threshold}

    flagged = modules | kev | epss
    print(f"Metasploit module : {len(modules)}")
    print(f"KEV (exploited)   : {len(kev)}")
    print(f"EPSS >= {args.epss_threshold}      : {len(epss)}")
    print(f"flagged by all three : {len(modules & kev & epss)}")
    print(f"flagged by exactly one: "
          f"{len(modules - kev - epss) + len(kev - modules - epss) + len(epss - modules - kev)}")
    print(f"flagged by nothing    : {len(rows) - len(flagged)} of {len(rows)}")

    figures.signal_agreement(modules, kev, epss, population=len(rows),
                             epss_threshold=args.epss_threshold,
                             out_dir=R("figures"))


if __name__ == "__main__":
    main()
