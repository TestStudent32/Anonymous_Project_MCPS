#!/usr/bin/env python3
"""
What medical software does Metasploit target at all? Offline.

The coverage measurement goes from CVEs to modules. This goes the other way:
it scans every module in the framework for medical software, independently of
any CVE set, so the coverage result cannot be an artifact of how those sets were
assembled.

    python run/reverse_lookup.py
    python run/reverse_lookup.py --show-ambiguous    # list the rejected matches
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from iomt_exploit import reverse_lookup

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
METADATA = os.path.join(HERE, "data", "msf", "modules_metadata_base.json")
OUT = os.path.join(HERE, "results", "metasploit_medical_modules.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--show-ambiguous", action="store_true")
    args = ap.parse_args()

    metadata = json.load(open(METADATA, encoding="utf-8"))
    found = reverse_lookup.scan(metadata)
    stats = reverse_lookup.summarise(found, len(metadata))

    print(f"{stats['medical_modules']} of {stats['modules_total']} modules name medical "
          f"software ({stats['medical_pct']}%)")
    print(f"  naming a device vendor : {stats['naming_a_device_vendor']}")
    print(f"  by type                : {stats['by_type']}\n")

    for fullname, module in sorted(found["medical"].items()):
        date = module.get("disclosure_date") or "?"
        print(f"  {date:10s}  {fullname[:52]:52s}  {','.join(module['terms'])}")

    if args.show_ambiguous:
        print(f"\nrejected as ambiguous ({stats['ambiguous_needing_review']}):")
        for fullname, module in sorted(found["ambiguous"].items()):
            print(f"  {fullname[:60]:60s}  {','.join(module['terms'])}")

    json.dump({"summary": stats, **found}, open(OUT, "w", encoding="utf-8"), indent=1)
    print(f"\n-> {os.path.relpath(OUT, HERE)}")


if __name__ == "__main__":
    main()
