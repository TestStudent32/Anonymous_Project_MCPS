#!/usr/bin/env python3
"""
Which channel publishes a medical vulnerability first, CISA or NVD? Offline.

    python run/analyse_timing.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from iomt_exploit import timing

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GROUND_TRUTH = os.path.join(HERE, "results", "cisa_icsma_cves.json")
OUT = os.path.join(HERE, "results", "disclosure_timing.json")


def main():
    ground_truth = json.load(open(GROUND_TRUTH, encoding="utf-8"))
    lag_by_cve = timing.lags(ground_truth)
    stats = timing.summarise(lag_by_cve)
    per_year = timing.by_year(ground_truth, lag_by_cve)

    print(f"{stats['cves']} CVEs carry both an advisory date and an NVD date\n")
    print(f"  advisory published FIRST : {stats['advisory_first']:3d} "
          f"({stats['advisory_first_pct']}%)")
    print(f"  same day                 : {stats['same_day']:3d}")
    print(f"  NVD published first      : {stats['nvd_first']:3d}")
    print(f"\n  median lag  : {stats['median_days']:+.0f} days "
          f"(negative = advisory first)")
    print(f"  quartiles   : {stats['q1_days']:+d} .. {stats['q3_days']:+d} days")
    print(f"  range       : {stats['min_days']:+d} .. {stats['max_days']:+d} days")
    print(f"  within a week either way: {stats['within_a_week_either_way']}")

    print("\nby advisory year:")
    for year, v in per_year.items():
        print(f"  {year}  {v['cves']:3d} CVEs  median {v['median_days']:+.0f} days")

    json.dump({"summary": stats, "by_year": per_year, "lag_days": lag_by_cve},
              open(OUT, "w", encoding="utf-8"), indent=1)
    print(f"\n-> {os.path.relpath(OUT, HERE)}")


if __name__ == "__main__":
    main()
