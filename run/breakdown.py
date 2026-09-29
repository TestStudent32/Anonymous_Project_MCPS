#!/usr/bin/env python3
"""
Where the coverage sits: by device class, by protocol, and by what the CVE
actually affects. Offline.

Two cuts, because the two CVE sets carry different information:

* the 1,281-CVE medical set has a device class per CVE (pumps, monitors,
  imaging, and the DICOM and HL7 protocol classes), so coverage can be split
  by class;
* the 341-CVE curated set has CPE part letters, which say whether a CVE
  affects an application, an operating system or hardware -- the distinction
  that matters here, since Metasploit's medical modules all target
  applications.

    python run/breakdown.py
"""
import csv
import json
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VALID = os.path.join(HERE, "results", "medical_valid_cves.csv")
PROFILE = os.path.join(HERE, "results", "cisa_exploitability_profile.json")
OUT = os.path.join(HERE, "results", "breakdown.json")

CLASS_NAMES = {
    "IOMT-INFUSION-PUMP": "Infusion / insulin pump",
    "IOMT-PATIENT-MONITOR": "Patient monitor",
    "IOMT-IMAGING-PACS": "Imaging / PACS",
    "IOMT-CARDIAC-IMPLANT": "Cardiac implant / programmer",
    "IOMT-VENTILATOR": "Ventilator / anaesthesia",
    "IOMT-GLUCOSE-CGM": "Glucose meter / CGM",
    "IOMT-EHR-GATEWAY": "EHR / HL7 gateway",
    "IOMT-DIAGNOSTIC-LAB": "Diagnostic analyser",
    "IOMT-PROTO-DICOM": "DICOM (protocol)",
    "IOMT-PROTO-HL7": "HL7 / FHIR (protocol)",
}

PART_NAMES = {"a": "application", "o": "operating system", "h": "hardware"}


def main():
    rows = list(csv.DictReader(open(VALID, encoding="utf-8")))

    # --- coverage by device class (a CVE can belong to more than one) -------
    per_class = defaultdict(lambda: {"cves": 0, "with_module": 0})
    for row in rows:
        covered = row["msf_module_count"] not in ("", "0")
        for cls in filter(None, row["device_classes"].split(";")):
            per_class[cls]["cves"] += 1
            per_class[cls]["with_module"] += int(covered)

    print("coverage by device class (1,281 valid medical CVEs)\n")
    print(f"  {'class':30s} {'CVEs':>6s} {'module':>7s} {'%':>6s}")
    table = {}
    for cls, v in sorted(per_class.items(), key=lambda kv: -kv[1]["cves"]):
        pct = round(100 * v["with_module"] / v["cves"], 1) if v["cves"] else 0.0
        table[cls] = dict(v, coverage_pct=pct, name=CLASS_NAMES.get(cls, cls))
        print(f"  {CLASS_NAMES.get(cls, cls):30s} {v['cves']:6d} {v['with_module']:7d} {pct:5.1f}%")

    # --- what the curated set affects --------------------------------------
    profile = json.load(open(PROFILE, encoding="utf-8"))
    parts = Counter()
    for record in profile.values():
        if not record["parts"]:
            parts["(no CPE recorded)"] += 1
        else:
            parts[" + ".join(PART_NAMES.get(p, p) for p in record["parts"])] += 1

    print("\nwhat the 341 curated CVEs affect (CPE part)\n")
    for label, n in parts.most_common():
        print(f"  {label:34s} {n:4d}  {round(100*n/len(profile)):3d}%")

    json.dump({"by_device_class": table,
               "curated_set_by_cpe_part": dict(parts)},
              open(OUT, "w", encoding="utf-8"), indent=1)
    print(f"\n-> {os.path.relpath(OUT, HERE)}")


if __name__ == "__main__":
    main()
