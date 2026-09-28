#!/usr/bin/env python3
"""
Rebuild the exploitability profile of the ground truth from NVD. Needs the network.

For every ground-truth CVE this records how it is reachable (CVSS attack
vector), what kind of weakness it is (CWE), what it affects (CPE part) and how
severe it is. Those four fields are what the mechanism argument rests on.

    python run/build_profile.py
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from iomt_exploit import nvd, profile as prof

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GROUND_TRUTH = os.path.join(HERE, "results", "cisa_icsma_cves.json")
OUT = os.path.join(HERE, "results", "cisa_exploitability_profile.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"))
    ap.add_argument("--refresh", action="store_true", help="re-fetch every CVE")
    args = ap.parse_args()

    ids = sorted(c.upper() for c in json.load(open(GROUND_TRUTH, encoding="utf-8")))
    have = {} if args.refresh or not os.path.exists(OUT) else json.load(open(OUT, encoding="utf-8"))
    todo = [c for c in ids if c not in have]
    print(f"{len(ids)} ground-truth CVEs, {len(todo)} to fetch")

    for i, cve in enumerate(todo, 1):
        entry = nvd.get(cve, args.api_key)
        if entry:
            have[cve] = prof.profile_entry(entry)
        if i % 50 == 0:
            json.dump(have, open(OUT, "w", encoding="utf-8"), indent=1)
            print(f"  {i}/{len(todo)}")
        time.sleep(0.7 if args.api_key else 6.5)

    json.dump(have, open(OUT, "w", encoding="utf-8"), indent=1)
    stats = prof.mechanism(have)

    print(f"\nprofiled {stats['total']} CVEs\n")
    for vector, v in stats["attack_vector"].items():
        print(f"  {vector:18s} {v['n']:4d}  {v['pct']:3d}%")
    d, t, s = stats["design_flaws"], stats["plausible_module_targets"], stats["high_or_critical"]
    print(f"\n  credential/design flaws  {d['n']:4d}  {d['pct']:3d}%  "
          f"({d['pct_of_network_reachable']}% of the network-reachable ones)")
    print(f"  plausible module targets {t['n']:4d}  {t['pct']:3d}%  "
          f"(network-reachable AND an implementation bug)")
    print(f"  high or critical         {s['n']:4d}  {s['pct']:3d}%")
    print(f"\n-> {os.path.relpath(OUT, HERE)}")


if __name__ == "__main__":
    main()
