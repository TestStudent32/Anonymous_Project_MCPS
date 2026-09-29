#!/usr/bin/env python3
"""
Re-derive every number the paper prints, from the shipped data. Offline.

Each line shows what the artifact computes against what the paper claims, and
the script exits non-zero if any of them disagree. This is the fastest way for
a reviewer to check the paper: no API key, no network, no Metasploit install.

    python run/verify_paper_numbers.py
"""
import csv
from collections import Counter
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
    check("  excluding certificate/crypto issues",
          stats["plausible_module_targets"]["excluding_crypto"], 92)
    check("credential/design flaw count", stats["design_flaws"]["n"], 132)
    check("high or critical count", stats["high_or_critical"]["n"], 170)
    check("high or critical pct", stats["high_or_critical"]["pct"], 50, 0.5)

    print("\n=== WHICH CHANNEL PUBLISHES FIRST ===")
    from iomt_exploit import timing
    lag = timing.lags(ground_truth)
    t = timing.summarise(lag)
    check("CVEs with both dates", t["cves"], 341)
    check("advisory published first", t["advisory_first"], 286)
    check("  as pct", t["advisory_first_pct"], 83.9, 0.05)
    check("same day", t["same_day"], 55)
    check("NVD published first", t["nvd_first"], 0)
    check("median lag (days, negative = advisory first)", t["median_days"], -6, 0.5)

    print("\n=== WHAT METASPLOIT TARGETS, ASKED IN REVERSE ===")
    from iomt_exploit import reverse_lookup
    metadata = json.load(open(R("data", "msf", "modules_metadata_base.json"), encoding="utf-8"))
    found = reverse_lookup.scan(metadata)
    rev = reverse_lookup.summarise(found, len(metadata))
    check("modules in the framework", rev["modules_total"], 7158)
    check("modules naming medical software", rev["medical_modules"], 8)
    check("modules naming a medical device vendor", rev["naming_a_device_vendor"], 0)

    print("\n=== THE OTHER PUBLIC EXPLOITATION SIGNALS ===")
    sig_path = R("results", "exploit_signals.json")
    if os.path.exists(sig_path):
        s = json.load(open(sig_path, encoding="utf-8"))
        check("curated CVEs in CISA KEV", s["kev"]["curated"]["in_kev"], 0)
        check("valid medical CVEs in KEV", s["kev"]["valid"]["in_kev"], 8)
        check("  of which carry a module", s["kev"]["with_metasploit_module"]["in_kev"], 7)
        check("EPSS median, curated set", s["epss"]["curated"]["median"], 0.005, 0.0005)
        check("EPSS max, curated set", s["epss"]["curated"]["max"], 0.1278, 0.0005)
        check("curated CVEs with EPSS >= 0.5", s["epss"]["curated"]["at_or_above_0.5"], 0)
        check("EPSS median of the 15 with modules",
              s["epss"]["with_metasploit_module"]["median"], 0.8986, 0.0005)
        check("curated CVEs NVD tags with an Exploit reference",
              s["nvd_exploit_references"]["with_exploit_reference"], 0)

        # Signal agreement, as drawn in the Venn.
        modules = {r["cve_id"].upper() for r in valid if r["msf_module_count"] not in ("", "0")}
        kev = set(s["kev"]["valid"]["cves"])
        epss = {c for c, v in s["epss"]["scores_valid"].items() if float(v) >= 0.5}
        check("flagged by all three signals", len(modules & kev & epss), 7)
        check("flagged by exactly one",
              len(modules - kev - epss) + len(kev - modules - epss) + len(epss - modules - kev), 22)
        check("flagged by no signal", len(valid) - len(modules | kev | epss), 1250)

    print("\n=== COVERAGE BY DEVICE CLASS (the paper's class table) ===")
    per_class = {}
    for row in valid:
        covered = row["msf_module_count"] not in ("", "0")
        for cls in filter(None, row["device_classes"].split(";")):
            slot = per_class.setdefault(cls, [0, 0])
            slot[0] += 1
            slot[1] += int(covered)
    # class: (CVEs, with module) exactly as printed in the paper
    for cls, (cves, mods) in {
        "IOMT-IMAGING-PACS": (627, 9), "IOMT-EHR-GATEWAY": (377, 5),
        "IOMT-PROTO-DICOM": (162, 2), "IOMT-INFUSION-PUMP": (144, 2),
        "IOMT-PATIENT-MONITOR": (136, 1), "IOMT-PROTO-HL7": (54, 2),
        "IOMT-GLUCOSE-CGM": (129, 0), "IOMT-CARDIAC-IMPLANT": (62, 0),
        "IOMT-DIAGNOSTIC-LAB": (39, 0), "IOMT-VENTILATOR": (32, 0),
    }.items():
        check(f"{cls} CVEs", per_class[cls][0], cves)
        check(f"  with a module", per_class[cls][1], mods)

    print("\n=== THE EIGHT MEDICAL MODULES (the paper's module table) ===")
    medical_modules = found["medical"]
    check("medical modules listed", len(medical_modules), 8)
    for fragment, year in [("openemr_upload_exec", "2013"),
                           ("openemr_sqli_privesc_upload", "2013"),
                           ("dicoogle_traversal", "2018"),
                           ("openmrs_deserialization", "2019"),
                           ("openemr_sqli_dump", "2019"),
                           ("clinic_pms_fileupload_rce", "2022"),
                           ("clinic_pms_sqli_to_rce", "2025"),
                           ("pacsserver_traversal", "2025")]:
        match = [m for name, m in medical_modules.items() if fragment in name]
        check(f"{fragment} present", len(match), 1)
        if match:
            check(f"  disclosed {year}", (match[0].get("disclosure_date") or "")[:4], year)

    print("\n=== THE DENOMINATORS ARE NOT INFLATED BY WHAT WE MEASURE ===")
    # Admission to either valid set is decided by relevance; the exploit tier is
    # recorded afterwards. These CVEs have modules and were still excluded.
    den_path = R("results", "denominator_check.json")
    if os.path.exists(den_path):
        den = json.load(open(den_path, encoding="utf-8"))
        check("medical CVEs excluded as irrelevant despite a module",
              len(den["medical"]["excluded_as_irrelevant_despite_module"]), 35)
        check("consumer CVEs excluded as irrelevant despite a module",
              len(den["consumer"]["excluded_as_irrelevant_despite_module"]), 71)

    print("\n=== WHAT THE CURATED SET AFFECTS ===")
    parts = Counter()
    for record in profile.values():
        parts["none" if not record["parts"] else "+".join(record["parts"])] += 1
    n = len(profile)
    check("hardware + OS share %", round(100 * parts["h+o"] / n), 42, 0.5)
    check("application-only share %", round(100 * parts["a"] / n), 34, 0.5)
    check("no CPE recorded share %", round(100 * parts["none"] / n), 16, 0.5)

    print("\n=== THE THIRD POPULATION: INDUSTRIAL CONTROL SYSTEMS ===")
    ind_path = R("results", "industrial_comparison.json")
    if os.path.exists(ind_path):
        ind = json.load(open(ind_path, encoding="utf-8"))["industrial"]
        check("industrial CVEs (ICSA-referenced)", ind["cves"], 3429)
        check("industrial CVEs with a module", ind["metasploit"], 48)
        check("  coverage %", ind["coverage_pct"], 1.4, 0.05)
        check("industrial CVEs in KEV", ind["kev"], 9)
        check("industrial design-failure share %", ind["weakness"]["design"]["pct"], 21.7, 0.05)
        check("industrial implementation share %",
              ind["weakness"]["implementation"]["pct"], 38.2, 0.05)
        check("industrial network-reachable %",
              ind["mechanism"]["attack_vector"]["NETWORK"]["pct"], 71, 0.5)
        check("industrial plausible module targets",
              ind["mechanism"]["plausible_module_targets"]["n"], 1845)

    print("\n=== HOW MEDICAL AND CONSUMER DEVICES FAIL ===")
    from iomt_exploit import weakness_profile as wp
    med = wp.profile([v["cwes"] for v in profile.values()])
    con = wp.profile([v["cwes"] for v in json.load(
        open(R("results", "consumer_iot_cves.json"), encoding="utf-8")).values()])
    check("medical: credential/design share %", med["design"]["pct"], 38.8, 0.05)
    check("medical: implementation share %", med["implementation"]["pct"], 16.2, 0.05)
    check("consumer: credential/design share %", con["design"]["pct"], 13.0, 0.05)
    check("consumer: implementation share %", con["implementation"]["pct"], 51.5, 0.05)

    print("\n" + "=" * 60)
    print(f"PASS {len(OK)}   FAIL {len(BAD)}")
    for label in BAD:
        print(f"  MISMATCH {label}")
    sys.exit(1 if BAD else 0)


if __name__ == "__main__":
    main()
