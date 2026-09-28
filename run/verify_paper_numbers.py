#!/usr/bin/env python3
"""
Re-derive every number the paper prints, from the shipped data. Offline.

Each line shows what the artifact computes against what the paper claims, and
the script exits non-zero if any of them disagree. This is the fastest way for
a reviewer to check the paper: no API key, no network, no Metasploit install.

    python run/verify_paper_numbers.py
"""
import csv
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from iomt_exploit import metasploit, profile as prof

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = lambda *p: os.path.join(HERE, *p)

OK, BAD = [], []


def check(label, got, want, tol=0.0):
    good = abs(got - want) <= tol if isinstance(want, (int, float)) else got == want
    (OK if good else BAD).append(label)
    print(f"  {'OK  ' if good else 'FAIL'} {label}: artifact={got} paper={want}")


def main():
    ground_truth = json.load(open(R("results", "cisa_icsma_cves.json"), encoding="utf-8"))
    gt_ids = {c.upper() for c in ground_truth}
    valid = list(csv.DictReader(open(R("results", "medical_valid_cves.csv"), encoding="utf-8")))
    profile = json.load(open(R("results", "cisa_exploitability_profile.json"), encoding="utf-8"))

    print("\n=== GROUND TRUTH ===")
    advisories = {a for v in ground_truth.values() for a in v["advisories"]}
    check("CISA-curated medical CVEs", len(gt_ids), 341)
    check("distinct ICSMA advisories", len(advisories), 138)

    print("\n=== COVERAGE ===")
    index = metasploit.build_index(json.load(open(R("data", "msf", "modules_metadata_base.json"),
                                                  encoding="utf-8")))
    cisa_cov = metasploit.coverage(gt_ids, index)
    valid_cov = metasploit.coverage({r["cve_id"].upper() for r in valid}, index)
    consumer = json.load(open(R("results", "msf_live_consumer.json"), encoding="utf-8"))["enrichment"]
    check("valid medical CVEs", valid_cov["cves"], 1281)
    check("valid medical CVEs with a module", valid_cov["with_module"], 15)
    check("  as pct", valid_cov["coverage_pct"], 1.2, 0.05)
    check("CISA-curated CVEs with a module", cisa_cov["with_module"], 0)
    check("consumer IoT coverage pct", consumer["coverage_pct_live"], 26.0, 0.05)

    print("\n=== LIVE VERIFICATION (Metasploit 6.5.3 over msfrpcd) ===")
    live = json.load(open(R("results", "msf_live_medical.json"), encoding="utf-8"))
    valid_live, cisa_live = live["iomt_valid"], live["cisa_ground_truth"]
    check("live coverage of the valid set", valid_live["enrichment"]["cves_with_module_live"], 15)
    check("live coverage of the CISA set", cisa_live["enrichment"]["cves_with_module_live"], 0)
    check("modules ranked Good or better", valid_live["enrichment"]["cves_with_reliable_module"], 9)
    # A disagreement either way would mean the metadata snapshot had drifted
    # from the installed modules, so both directions are checked.
    check("live finds nothing the snapshot missed", len(valid_live["offline_vs_live"]["live_only"]), 0)
    check("snapshot finds nothing live missed", len(valid_live["offline_vs_live"]["offline_only"]), 0)

    print("\n=== WHY THE ZERO HAPPENS ===")
    stats = prof.mechanism(profile)
    check("profile covers the ground truth", stats["total"], 341)
    check("network-reachable pct", stats["attack_vector"]["NETWORK"]["pct"], 50, 0.5)
    check("adjacent pct", stats["attack_vector"]["ADJACENT_NETWORK"]["pct"], 20, 0.5)
    check("local pct", stats["attack_vector"]["LOCAL"]["pct"], 16, 0.5)
    check("physical pct", stats["attack_vector"]["PHYSICAL"]["pct"], 14, 0.5)
    check("credential/design flaw pct", stats["design_flaws"]["pct"], 39, 0.5)
    check("  as pct of network-reachable", stats["design_flaws"]["pct_of_network_reachable"], 40, 0.5)
    check("plausible module targets", stats["plausible_module_targets"]["n"], 102)
    check("  as pct", stats["plausible_module_targets"]["pct"], 30, 0.5)
    check("high or critical pct", stats["high_or_critical"]["pct"], 50, 0.5)

    print("\n" + "=" * 60)
    print(f"PASS {len(OK)}   FAIL {len(BAD)}")
    for label in BAD:
        print(f"  MISMATCH {label}")
    sys.exit(1 if BAD else 0)


if __name__ == "__main__":
    main()
