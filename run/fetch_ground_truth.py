#!/usr/bin/env python3
"""
Rebuild the CISA ICSMA ground truth from NVD. Needs the network.

The shipped results/cisa_icsma_cves.json is a September 2026 snapshot, so this
will return slightly more CVEs than the paper reports: CISA publishes
continuously. Re-running it is how you check the extraction itself, not how you
reproduce the paper's numbers -- for that use run/verify_paper_numbers.py.

    python run/fetch_ground_truth.py                  # writes a dated file
    python run/fetch_ground_truth.py --overwrite      # replace the snapshot
"""
import argparse
import json
import os
import sys
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from iomt_exploit import ground_truth

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAPSHOT = os.path.join(HERE, "results", "cisa_icsma_cves.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--overwrite", action="store_true",
                    help="replace the shipped snapshot instead of writing a dated file")
    ap.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"),
                    help="an NVD API key raises the rate limit from ~5 to 50 requests/30s")
    args = ap.parse_args()

    print("paging every CISA ICS-CERT CVE in NVD (this takes a few minutes) ...")
    found = ground_truth.build(args.api_key)
    summary = ground_truth.summarise(found)
    print(f"\n{summary['cves']} medical CVEs across {summary['advisories']} ICSMA advisories")
    print(f"by year: {summary['by_year']}")

    out = SNAPSHOT if args.overwrite else os.path.join(
        HERE, "results", f"cisa_icsma_cves_{date.today().isoformat()}.json")
    json.dump(found, open(out, "w", encoding="utf-8"), indent=1)
    print(f"-> {os.path.relpath(out, HERE)}")

    if not args.overwrite and os.path.exists(SNAPSHOT):
        old = {c.upper() for c in json.load(open(SNAPSHOT, encoding="utf-8"))}
        new = {c.upper() for c in found}
        print(f"\nagainst the shipped snapshot: +{len(new - old)} new, "
              f"-{len(old - new)} withdrawn")


if __name__ == "__main__":
    main()
