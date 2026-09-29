#!/usr/bin/env python3
"""
Ask every public exploitation signal about the same CVEs. Needs the network.

Metasploit coverage is one proxy. This checks the others a defender could use:
CISA's KEV catalog (observed exploitation), EPSS (predicted exploitation), and
NVD's own ``Exploit`` reference tag.

    python run/analyse_signals.py
    python run/analyse_signals.py --skip-nvd     # KEV and EPSS only (fast)
"""
import argparse
import csv
import datetime
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from iomt_exploit import exploit_signals as sig, nvd

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = lambda *p: os.path.join(HERE, *p)
OUT = R("results", "exploit_signals.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"))
    ap.add_argument("--skip-nvd", action="store_true",
                    help="skip the NVD reference-tag pass (341 requests)")
    args = ap.parse_args()

    curated = {c.upper() for c in json.load(open(R("results", "cisa_icsma_cves.json"),
                                                 encoding="utf-8"))}
    rows = list(csv.DictReader(open(R("results", "medical_valid_cves.csv"), encoding="utf-8")))
    valid = {r["cve_id"].upper() for r in rows}
    with_module = {r["cve_id"].upper() for r in rows if r["msf_module_count"] not in ("", "0")}

    # Merge into any previous run, so a --skip-nvd pass does not discard the
    # (slow) NVD reference results.
    result = json.load(open(OUT, encoding="utf-8")) if os.path.exists(OUT) else {}
    # KEV grows and EPSS is recomputed daily, so these results are only
    # meaningful with the date they were fetched.
    result["measured_on"] = datetime.date.today().isoformat()

    # ---- KEV ------------------------------------------------------------
    print("fetching CISA KEV ...")
    kev = sig.fetch_kev()
    result["kev"] = {
        "catalog_size": len(kev),
        "curated": sig.kev_overlap(curated, kev),
        "valid": sig.kev_overlap(valid, kev),
        "with_metasploit_module": sig.kev_overlap(with_module, kev),
    }
    print(f"  KEV holds {len(kev)} CVEs")
    print(f"  curated set (341)      : {result['kev']['curated']['in_kev']} in KEV")
    print(f"  valid set (1,281)      : {result['kev']['valid']['in_kev']} in KEV")
    print(f"  the 15 with modules    : {result['kev']['with_metasploit_module']['in_kev']} in KEV")
    for cve, meta in result["kev"]["valid"]["cves"].items():
        print(f"     {cve}  {meta['vendor']:18s} added {meta['date_added']}")

    # ---- EPSS -----------------------------------------------------------
    print("\nfetching EPSS ...")
    epss_curated = sig.fetch_epss(curated)
    epss_valid = sig.fetch_epss(valid)
    result["epss"] = {
        "curated": sig.epss_summary(epss_curated),
        "valid": sig.epss_summary(epss_valid),
        "with_metasploit_module": sig.epss_summary(
            {c: epss_valid[c] for c in with_module if c in epss_valid}),
        # Kept per CVE so the signal-agreement figure can be drawn offline.
        "scores_curated": epss_curated,
        "scores_valid": epss_valid,
    }
    for label in ("curated", "valid", "with_metasploit_module"):
        s = result["epss"][label]
        print(f"  {label:24s} median {s['median']:.4f}  max {s['max']:.4f}  "
              f">=0.5: {s['at_or_above_0.5']}")

    # ---- NVD exploit references ----------------------------------------
    if not args.skip_nvd:
        print(f"\nfetching NVD references for {len(curated)} curated CVEs ...")
        entries = {}
        for i, cve in enumerate(sorted(curated), 1):
            entry = nvd.get(cve, args.api_key)
            if entry:
                entries[cve] = entry
            if i % 100 == 0:
                print(f"  {i}/{len(curated)}")
            time.sleep(0.7 if args.api_key else 6.5)
        result["nvd_exploit_references"] = sig.exploit_reference_overlap(entries)
        r = result["nvd_exploit_references"]
        print(f"  {r['with_exploit_reference']} of {r['checked']} curated CVEs have a "
              f"reference NVD tags as Exploit ({r['pct']}%)")

    json.dump(result, open(OUT, "w", encoding="utf-8"), indent=1)
    print(f"\n-> {os.path.relpath(OUT, HERE)}")


if __name__ == "__main__":
    main()
