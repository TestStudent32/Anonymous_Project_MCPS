#!/usr/bin/env python3
"""
Regenerate both figures from the shipped results. Offline.

    python run/make_figures.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from iomt_exploit import figures, profile as prof

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COVERAGE = os.path.join(HERE, "results", "coverage.json")
PROFILE = os.path.join(HERE, "results", "cisa_exploitability_profile.json")
FIG_DIR = os.path.join(HERE, "figures")


def main():
    if not os.path.exists(COVERAGE):
        sys.exit("run/check_coverage.py first (it writes results/coverage.json)")

    coverage = json.load(open(COVERAGE, encoding="utf-8"))
    figures.coverage_collapse(
        consumer=(coverage["consumer_iot"]["with_module"], coverage["consumer_iot"]["cves"]),
        medical_valid=(coverage["medical_valid"]["with_module"], coverage["medical_valid"]["cves"]),
        cisa=(coverage["cisa_curated"]["with_module"], coverage["cisa_curated"]["cves"]),
        out_dir=FIG_DIR)

    stats = prof.mechanism(json.load(open(PROFILE, encoding="utf-8")))
    figures.mechanism(stats, out_dir=FIG_DIR)


if __name__ == "__main__":
    main()
