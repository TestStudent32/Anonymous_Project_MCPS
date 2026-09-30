#!/usr/bin/env python3
"""
Reconcile our ground truth against the published dataset of prior work.

Bracciale et al. (Sci. Rep. 15:42635, 2025) assemble 470 medical CVEs by
scraping CISA, where we recover 341 through NVD. They publish their dataset, so
the two extractions can be compared directly rather than described, and their
per-CVE threat classification gives an independent check on our four signals:
if a CVE they class as having public exploit code is invisible to all four of
ours, that is evidence about the signals rather than about the vulnerability.

    python run/reconcile_prior_work.py          # downloads their CSV once
    python run/reconcile_prior_work.py --reuse
"""
import argparse
import csv
import io
import json
import os
import sys
import urllib.request
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = lambda *p: os.path.join(HERE, *p)
THEIRS_URL = ("https://raw.githubusercontent.com/netgroup/medical-device-cvss4bte/"
              "HEAD/datasets/CVSSv4_BTE_full_list.csv")
CACHE = R("results", "prior_work_dataset.csv")
OUT = R("results", "prior_work_reconciliation.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reuse", action="store_true")
    args = ap.parse_args()

    if not (args.reuse and os.path.exists(CACHE)):
        print(f"fetching {THEIRS_URL}")
        data = urllib.request.urlopen(THEIRS_URL, timeout=90).read().decode("utf-8-sig")
        open(CACHE, "w", encoding="utf-8", newline="").write(data)
    rows = list(csv.DictReader(open(CACHE, encoding="utf-8-sig"), delimiter=";"))

    theirs = {r["CVE_ID"].strip().upper(): r for r in rows if r.get("CVE_ID")}
    ours = {c.upper() for c in json.load(open(R("results", "cisa_icsma_cves.json"),
                                              encoding="utf-8"))}
    shared = set(theirs) & ours

    print(f"\ntheir set {len(theirs)}, our set {len(ours)}")
    print(f"  shared        {len(shared)}")
    print(f"  only theirs   {len(set(theirs) - ours)}")
    print(f"  only ours     {len(ours - set(theirs))}")

    recent = sum(1 for c in ours - set(theirs) if c.split("-")[1] >= "2025")
    print(f"    of which published 2025 or later: {recent}")

    # Their threat classification: A = attacked, P = public exploit code, U = neither.
    classes = Counter(r["Threat"].strip() for r in rows)
    shared_classes = Counter(theirs[c]["Threat"].strip() for c in shared)
    print(f"\ntheir threat classes, all {len(theirs)}: {dict(classes)}")
    print(f"  over the {len(shared)} shared: {dict(shared_classes)}")

    # The check that matters: CVEs they say have exploit material, that none of
    # our four signals flags.
    signals = json.load(open(R("results", "exploit_signals.json"), encoding="utf-8"))
    epss = signals["epss"]["scores_curated"]
    kev = set(signals["kev"]["curated"]["cves"])
    flagged = []
    for c in sorted(shared):
        if theirs[c]["Threat"].strip() in ("A", "P"):
            flagged.append({"cve": c, "their_class": theirs[c]["Threat"].strip(),
                            "their_epss": theirs[c].get("EPSS"),
                            "our_epss": epss.get(c), "in_kev": c in kev,
                            "product": theirs[c].get("Affected_Products", "")[:70]})
    print(f"\nshared CVEs they class as having exploit material: {len(flagged)}")
    for f in flagged:
        print(f"  {f['cve']}  class {f['their_class']}  our EPSS {f['our_epss']}  "
              f"KEV {f['in_kev']}  {f['product']}")

    json.dump({"theirs": len(theirs), "ours": len(ours), "shared": len(shared),
               "only_theirs": len(set(theirs) - ours), "only_ours": len(ours - set(theirs)),
               "only_ours_2025_or_later": recent,
               "their_classes_all": dict(classes), "their_classes_shared": dict(shared_classes),
               "shared_with_exploit_material": flagged},
              open(OUT, "w", encoding="utf-8"), indent=1)
    print(f"\n-> {os.path.relpath(OUT, HERE)}")


if __name__ == "__main__":
    main()
