#!/usr/bin/env python3
"""
Audit *why* each CVE in prior work's dataset is missing from our extraction.

Our ground truth is recovered by paging NVD for records whose sourceIdentifier
is CISA's (ics-cert@hq.dhs.gov) and keeping those that cite an ICSMA advisory.
Two different mechanisms can therefore exclude a CVE that CISA really did
publish a medical advisory for:

  A. the NVD record is attributed to a different source (the vendor CNA, MITRE,
     a research CNA), so the source filter never returns it at all; or
  B. the record is CISA-sourced but its references do not cite an ICSMA
     advisory -- it cites only an ICSA one, or no advisory.

Prior work scrapes CISA directly and so is not subject to either. Saying "the
NVD record omits the ICSMA reference" for all of them would be a guess, so this
script asks NVD for each missing record and classifies it.

    python run/audit_exclusions.py --api-key $NVD_API_KEY
    python run/audit_exclusions.py --reuse
"""
import argparse
import csv
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = lambda *p: os.path.join(HERE, *p)
API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
CISA_SOURCE = "ics-cert@hq.dhs.gov"
ICSMA = re.compile(r"ICSMA-\d{2}-\d{3}-\d{2}", re.I)
ICSA = re.compile(r"ICSA-\d{2}-\d{3}-\d{2}", re.I)
CACHE = R("results", "exclusion_audit_records.json")
OUT = R("results", "exclusion_audit.json")


def fetch(cve, key, tries=4):
    req = urllib.request.Request(API + cve, headers={"apiKey": key} if key else {})
    for attempt in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            if attempt == tries - 1:
                return {"_error": str(exc)}
            time.sleep(2 + 3 * attempt)
    return {"_error": "unreachable"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"))
    ap.add_argument("--reuse", action="store_true")
    args = ap.parse_args()

    rows = list(csv.DictReader(open(R("results", "prior_work_dataset.csv"),
                                    encoding="utf-8-sig"), delimiter=";"))
    theirs = {r["CVE_ID"].strip().upper() for r in rows if r.get("CVE_ID")}
    ours = {c.upper() for c in json.load(open(R("results", "cisa_icsma_cves.json"),
                                              encoding="utf-8"))}
    industrial = set(json.load(open(R("results", "cisa_industrial_cves.json"),
                                    encoding="utf-8")))
    missing = sorted(theirs - ours)
    print(f"their set {len(theirs)}, ours {len(ours)}, missing from ours {len(missing)}")

    if args.reuse and os.path.exists(CACHE):
        records = json.load(open(CACHE, encoding="utf-8"))
        print(f"reusing {len(records)} cached NVD records")
    else:
        records = {}
        delay = 0.7 if args.api_key else 6.5
        for i, cve in enumerate(missing, 1):
            records[cve] = fetch(cve, args.api_key)
            if i % 25 == 0:
                print(f"  fetched {i}/{len(missing)}")
            time.sleep(delay)
        json.dump(records, open(CACHE, "w", encoding="utf-8"), indent=1)

    audit = {}
    for cve in missing:
        body = records.get(cve, {})
        vulns = body.get("vulnerabilities") or []
        if body.get("_error"):
            audit[cve] = {"reason": "query_failed", "detail": body["_error"][:80]}
            continue
        if not vulns:
            audit[cve] = {"reason": "not_in_nvd"}
            continue
        cvedata = vulns[0]["cve"]
        src = cvedata.get("sourceIdentifier", "")
        refs = " ".join(r.get("url", "") + " " + " ".join(r.get("tags", []))
                        for r in cvedata.get("references", []))
        has_icsma = bool(ICSMA.search(refs))
        has_icsa = bool(ICSA.search(refs))
        if src != CISA_SOURCE:
            reason = "source_not_cisa"
        elif not has_icsma:
            reason = "cisa_source_but_no_icsma_reference"
        else:
            # CISA-sourced and does cite an ICSMA advisory: our frozen snapshot
            # predates the record, or the extraction missed it.
            reason = "should_have_matched_snapshot_or_paging"
        audit[cve] = {"reason": reason, "source": src, "icsma_ref": has_icsma,
                      "icsa_ref": has_icsa, "status": cvedata.get("vulnStatus"),
                      "published": cvedata.get("published", "")[:10],
                      "in_our_industrial_set": cve in industrial}

    counts = {}
    for v in audit.values():
        counts[v["reason"]] = counts.get(v["reason"], 0) + 1
    print("\nwhy each of prior work's CVEs is absent from our extraction:")
    for reason, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {n:4d}  {reason}")

    sources = {}
    for v in audit.values():
        if v.get("reason") == "source_not_cisa":
            sources[v["source"]] = sources.get(v["source"], 0) + 1
    print("\nattributed instead to (top 10):")
    for s, n in sorted(sources.items(), key=lambda kv: -kv[1])[:10]:
        print(f"  {n:4d}  {s}")

    icsma_elsewhere = sum(1 for v in audit.values()
                          if v.get("reason") == "source_not_cisa" and v.get("icsma_ref"))
    print(f"\nof the non-CISA-sourced records, {icsma_elsewhere} do cite an ICSMA "
          f"advisory in their references")

    json.dump({"missing_total": len(missing), "reasons": counts,
               "other_sources": sources,
               "non_cisa_source_but_icsma_referenced": icsma_elsewhere,
               "per_cve": audit},
              open(OUT, "w", encoding="utf-8"), indent=1)
    print(f"\n-> {os.path.relpath(OUT, HERE)}")


if __name__ == "__main__":
    main()
