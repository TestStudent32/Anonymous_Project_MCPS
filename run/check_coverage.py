#!/usr/bin/env python3
"""
Measure Metasploit coverage of the medical CVE sets, offline.

Answers the paper's headline question from shipped data, with no network and no
running framework:

    how many of the CISA-curated medical CVEs have a Metasploit module?
    how many of the wider medical valid set do?
    how does that compare with consumer IoT on the same pipeline?

    python run/check_coverage.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from iomt_exploit import metasploit

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GROUND_TRUTH = os.path.join(HERE, "results", "cisa_icsma_cves.json")
VALID_CVES = os.path.join(HERE, "results", "medical_valid_cves.csv")
MSF_METADATA = os.path.join(HERE, "data", "msf", "modules_metadata_base.json")
CONSUMER = os.path.join(HERE, "results", "msf_live_consumer.json")
OUT = os.path.join(HERE, "results", "coverage.json")


def main():
    import csv

    print("building the CVE -> module index from Metasploit metadata ...")
    metadata = json.load(open(MSF_METADATA, encoding="utf-8"))
    index = metasploit.build_index(metadata)
    print(f"  {len(metadata)} modules, {len(index)} CVEs referenced\n")

    ground_truth = {c.upper() for c in json.load(open(GROUND_TRUTH, encoding="utf-8"))}
    valid = {r["cve_id"].upper() for r in csv.DictReader(open(VALID_CVES, encoding="utf-8"))}

    cisa_cov = metasploit.coverage(ground_truth, index)
    valid_cov = metasploit.coverage(valid, index)

    # Consumer IoT, measured by the same pipeline on the same framework version.
    consumer = json.load(open(CONSUMER, encoding="utf-8"))["enrichment"]

    print(f"CISA-curated medical : {cisa_cov['with_module']:4d} of {cisa_cov['cves']:4d} "
          f"({cisa_cov['coverage_pct']}%)")
    print(f"medical valid set    : {valid_cov['with_module']:4d} of {valid_cov['cves']:4d} "
          f"({valid_cov['coverage_pct']}%)")
    print(f"consumer IoT         : {consumer['cves_with_module_live']:4d} of "
          f"{consumer['valid_cve_count']:4d} ({consumer['coverage_pct_live']}%)")

    result = {
        "cisa_curated": cisa_cov,
        "medical_valid": valid_cov,
        "consumer_iot": {"cves": consumer["valid_cve_count"],
                         "with_module": consumer["cves_with_module_live"],
                         "coverage_pct": consumer["coverage_pct_live"]},
    }
    json.dump(result, open(OUT, "w", encoding="utf-8"), indent=1)
    print(f"\n-> {os.path.relpath(OUT, HERE)}")


if __name__ == "__main__":
    main()
