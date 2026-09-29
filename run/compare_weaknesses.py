#!/usr/bin/env python3
"""
Do medical and consumer devices fail in different ways? Offline.

    python run/compare_weaknesses.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from iomt_exploit import weakness_profile as wp

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = lambda *p: os.path.join(HERE, *p)
OUT = R("results", "weakness_comparison.json")


def main():
    medical_records = json.load(open(R("results", "cisa_exploitability_profile.json"),
                                     encoding="utf-8"))
    consumer_records = json.load(open(R("results", "consumer_iot_cves.json"), encoding="utf-8"))

    medical = wp.profile([v["cwes"] for v in medical_records.values()])
    consumer = wp.profile([v["cwes"] for v in consumer_records.values()])
    ratios = wp.compare(medical, consumer)

    print(f"{'population':18s} {'n':>5s} {'design':>9s} {'implementation':>15s} {'other':>8s}")
    for label, prof in (("medical (CISA)", medical), ("consumer IoT", consumer)):
        print(f"  {label:16s} {prof['cves_with_cwe']:5d} "
              f"{prof['design']['pct']:8.1f}% {prof['implementation']['pct']:14.1f}% "
              f"{prof['other']['pct']:7.1f}%")

    print(f"\nmedical CVEs are {ratios['design_ratio_medical_over_consumer']}x more likely to be a "
          f"credential or design failure")
    print(f"consumer CVEs are {ratios['implementation_ratio_consumer_over_medical']}x more likely "
          f"to be an implementation bug -- which is what an exploit module encodes")

    print("\ntop weaknesses")
    for label, prof in (("medical", medical), ("consumer", consumer)):
        print(f"  {label}: " + ", ".join(f"{w} ({n})" for w, n in prof["top_cwes"][:6]))

    json.dump({"medical": medical, "consumer": consumer, "ratios": ratios},
              open(OUT, "w", encoding="utf-8"), indent=1)
    print(f"\n-> {os.path.relpath(OUT, HERE)}")


if __name__ == "__main__":
    main()
