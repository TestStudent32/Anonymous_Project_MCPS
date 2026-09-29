#!/usr/bin/env python3
"""
Is the blind spot medical, or does it cover cyber-physical systems generally?

The medical ground truth is the ICSMA-referenced subset of CISA's ICS-CERT
CVEs. The rest of that same query -- advisories numbered ICSA rather than
ICSMA -- are the *industrial* control-system vulnerabilities: same publisher,
same coordination process, same kind of long-lived embedded device, different
sector. That makes them the natural third population, and one this study gets
almost for free.

If industrial CVEs are equally untouched by exploit modules and KEV, the
finding is about cyber-physical systems rather than about medicine. If they are
not, the medical result is genuinely distinctive and the flaw profile should
explain the difference.

Needs the network for the extraction, then reuses the shipped Metasploit index
and KEV/EPSS machinery.

    python run/industrial_comparison.py
    python run/industrial_comparison.py --reuse     # skip the NVD extraction
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from iomt_exploit import exploit_signals as sig, metasploit, nvd
from iomt_exploit import profile as prof, weakness_profile as wp

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = lambda *p: os.path.join(HERE, *p)
OUT = R("results", "industrial_comparison.json")
RAW = R("results", "cisa_industrial_cves.json")

CISA_SOURCE = "ics-cert@hq.dhs.gov"
ICSMA = re.compile(r"ICSMA-\d{2}-\d{3}-\d{2}[A-Z]?", re.I)
ICSA = re.compile(r"ICSA-\d{2}-\d{3}-\d{2}[A-Z]?", re.I)


def extract(api_key):
    """Every CISA-sourced CVE that cites an ICSA advisory and no ICSMA one."""
    industrial = {}
    seen = 0
    for entry in nvd.page_query({"sourceIdentifier": CISA_SOURCE}, api_key):
        seen += 1
        urls = " ".join(r.get("url", "") for r in entry.get("references") or [])
        if ICSMA.search(urls) or not ICSA.search(urls):
            continue            # medical, or not advisory-referenced at all
        industrial[entry["id"].upper()] = prof.profile_entry(entry)
        if seen % 1000 == 0:
            print(f"  scanned {seen} CISA CVEs, kept {len(industrial)} industrial")
    return industrial


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"))
    ap.add_argument("--reuse", action="store_true", help="use the saved extraction")
    args = ap.parse_args()

    if args.reuse and os.path.exists(RAW):
        industrial = json.load(open(RAW, encoding="utf-8"))
        print(f"{len(industrial)} industrial CVEs (from cache)")
    else:
        print("paging every CISA ICS-CERT CVE in NVD ...")
        industrial = extract(args.api_key)
        json.dump(industrial, open(RAW, "w", encoding="utf-8"), indent=1)
        print(f"{len(industrial)} industrial (ICSA-referenced, non-medical) CVEs")

    ids = set(industrial)

    # --- Metasploit, from the shipped index --------------------------------
    index = metasploit.build_index(json.load(open(R("data", "msf", "modules_metadata_base.json"),
                                                  encoding="utf-8")))
    cov = metasploit.coverage(ids, index)

    # --- KEV ---------------------------------------------------------------
    kev = sig.fetch_kev()
    kev_hit = sig.kev_overlap(ids, kev)

    # --- how they fail ------------------------------------------------------
    weak = wp.profile([v["cwes"] for v in industrial.values()])
    mech = prof.mechanism(industrial)

    medical = json.load(open(R("results", "cisa_exploitability_profile.json"), encoding="utf-8"))
    med_weak = wp.profile([v["cwes"] for v in medical.values()])
    med_mech = prof.mechanism(medical)

    print(f"\n{'':22s} {'industrial':>12s} {'medical':>10s}")
    print(f"  {'CVEs':20s} {len(ids):12d} {len(medical):10d}")
    print(f"  {'with a module':20s} {cov['with_module']:12d} {0:10d}")
    print(f"  {'  coverage':20s} {cov['coverage_pct']:11.1f}% {0.0:9.1f}%")
    print(f"  {'in KEV':20s} {kev_hit['in_kev']:12d} {0:10d}")
    print(f"  {'network-reachable %':20s} "
          f"{mech['attack_vector'].get('NETWORK', {}).get('pct', 0):12d} "
          f"{med_mech['attack_vector']['NETWORK']['pct']:10d}")
    print(f"  {'design failures %':20s} {weak['design']['pct']:12.1f} "
          f"{med_weak['design']['pct']:10.1f}")
    print(f"  {'implementation %':20s} {weak['implementation']['pct']:12.1f} "
          f"{med_weak['implementation']['pct']:10.1f}")

    json.dump({"industrial": {"cves": len(ids), "metasploit": cov["with_module"],
                              "coverage_pct": cov["coverage_pct"],
                              "kev": kev_hit["in_kev"], "kev_cves": list(kev_hit["cves"]),
                              "weakness": weak, "mechanism": mech},
               "medical": {"cves": len(medical), "metasploit": 0, "coverage_pct": 0.0,
                           "kev": 0, "weakness": med_weak, "mechanism": med_mech}},
              open(OUT, "w", encoding="utf-8"), indent=1)
    print(f"\n-> {os.path.relpath(OUT, HERE)}")


if __name__ == "__main__":
    main()
