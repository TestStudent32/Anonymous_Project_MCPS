#!/usr/bin/env python3
"""
Does the relevance scorer's exploit feature inflate consumer module coverage?

The consumer-IoT set was admitted by the generic relevance scorer, which awards
+0.15 when NVD records that an exploit is available, against a 0.4 threshold.
That makes exploit evidence part of the admission criterion, so the 26.0%
coverage figure could in principle be an artifact of its own denominator. (The
medical scorer is a separate path with no exploit feature, and the 341-CVE
curated set uses no scorer at all, so neither is affected.)

This script re-scores the consumer set with that feature forced off and reports
what the coverage rate would have been.

    python run/scorer_sensitivity.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from iomt_exploit import metasploit  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = lambda *p: os.path.join(HERE, *p)
OUT = R("results", "scorer_sensitivity.json")
THRESHOLD = 0.4
EXPLOIT_WEIGHT = 0.15


def confidence(detail: dict, grounding: dict, use_exploit: bool) -> float:
    """The generic (consumer) relevance score, reimplemented from the pipeline.

    +0.3 CWE overlap, +0.2 product keyword in the description, +0.2 CVSS >= 7.0,
    +0.15 exploit available, +0.15 protocol or target service named. Held here so
    the artifact does not depend on the withheld discovery pipeline.
    """
    score = 0.0
    if set(grounding.get("cve_search_cwes", [])) & set(detail.get("cwes", [])):
        score += 0.3
    desc = (detail.get("description") or "").lower()
    for prod in grounding.get("cve_relevant_products", []):
        if prod.replace("_", " ").lower() in desc:
            score += 0.2
            break
    if detail.get("cvss_score", 0) >= 7.0:
        score += 0.2
    if use_exploit and detail.get("exploit_available", False):
        score += EXPLOIT_WEIGHT
    for term in (grounding.get("protocol", ""), grounding.get("target_service", "")):
        term = (term or "").lower()
        if term and term not in ("any", "all") and term in desc:
            score += 0.15
            break
    return score


def main():
    details = json.load(open(R("data", "consumer", "nvd_details.json"), encoding="utf-8"))
    groundings = json.load(open(R("data", "consumer", "groundings.json"), encoding="utf-8"))
    index = {k.upper(): v for k, v in metasploit.build_index(
        json.load(open(R("data", "msf", "modules_metadata_base.json"), encoding="utf-8"))).items()}
    consumer = sorted(details)

    def kept(use_exploit):
        return [c for c in consumer
                if max((confidence(details[c], g, use_exploit) for g in groundings.values()),
                       default=0.0) >= THRESHOLD]

    rows = {}
    for label, use in (("as_published", True), ("exploit_feature_removed", False)):
        keep = kept(use)
        cov = [c for c in keep if c in index]
        rows[label] = {"cves": len(keep), "with_module": len(cov),
                       "coverage_pct": round(100 * len(cov) / len(keep), 1) if keep else 0.0}
        print(f"{label:26s} {len(keep):4d} CVEs  {len(cov):3d} with a module  "
              f"{rows[label]['coverage_pct']}%")

    dropped = sorted(set(kept(True)) - set(kept(False)))
    dropped_with_module = [c for c in dropped if c in index]
    print(f"\nadmitted only by the exploit feature: {len(dropped)}")
    print(f"  of those, with a Metasploit module : {len(dropped_with_module)}")
    print("\nThe feature changes membership but not the conclusion: removing it "
          f"moves coverage from {rows['as_published']['coverage_pct']}% to "
          f"{rows['exploit_feature_removed']['coverage_pct']}%.")

    json.dump({"threshold": THRESHOLD, "exploit_weight": EXPLOIT_WEIGHT, **rows,
               "admitted_only_by_exploit_feature": len(dropped),
               "of_those_with_module": len(dropped_with_module),
               "dropped_cves": dropped},
              open(OUT, "w", encoding="utf-8"), indent=1)
    print(f"\n-> {os.path.relpath(OUT, HERE)}")


if __name__ == "__main__":
    main()
