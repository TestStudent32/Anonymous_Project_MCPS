# Are medical-device vulnerabilities weaponised?

Artifact for the paper. It asks four public exploitation signals the same
question about the same medical CVEs, and finds all four silent — then tests how
much of that silence is a property of the signals rather than of the devices.

**The four signals, on 341 CVEs that CISA has published a medical advisory for**

| Signal | What it means | Result |
|---|---|---|
| Metasploit module | public exploit code exists | **0 of 341** |
| CISA KEV | exploitation observed in the wild | **0 of 341** |
| NVD `Exploit` reference tag | NVD *tags* a reference as exploit material | **0 of 341** |
| EPSS | predicted exploitation probability | median **0.005**, max 0.128 |

The tag is not the same as the link. Scanning the reference URLs themselves,
**one** of the 341 records cites Exploit-DB — a working proof-of-concept against
an infusion pump — which NVD tags "Third Party Advisory, VDB Entry" instead. So
the zero is a fact about the tag, not about the records.

For comparison, 1.4% of the 3,429 industrial ICS CVEs from the same advisory
extraction have a module, and 26% of a consumer-IoT set selected by an automated
relevance scorer do. The consumer figure carries selection caveats the industrial
one does not; see `scorer_sensitivity.json`.

**This is not evidence that the devices are safe.** KEV requires exploitation to
be detected, attributed and reported, which rarely happens for hospital
equipment, and EPSS is trained on signals a niche device flaw cannot produce.
Agreement between the signals shows the ecosystem has no visibility into these
devices — which is why triage for them cannot be driven by any of these signals.

**How the populations differ.** Medical CVEs are 3.0x more likely than
consumer-IoT ones to carry a credential or access-control weakness (38.8% vs
13.0%), and consumer CVEs 3.2x more likely to carry one of the implementation
weaknesses an exploit module encodes (51.5% vs 16.2%); the same direction holds
against the industrial set (21.7% and 38.2%), which is the comparison that does
not depend on a relevance scorer. Half the curated set carries a network attack
vector, and removing credential and access-control weaknesses leaves a residual
of 102 — an upper bound, not a count of implementation bugs, since only **33**
of the 102 carry an implementation-family weakness. This is an association across
populations that differ in more than device type, not a demonstrated cause.

## Verify the paper in one command

No API key, no network, no Metasploit install:

```bash
pip install -r requirements.txt
python run/verify_paper_numbers.py        # expect: PASS 133   FAIL 0
```

Every number in the paper is re-derived from `results/` and checked against what
the paper claims; the script exits non-zero on any mismatch.

## What each file does

```
iomt_exploit/            the logic, importable and testable
  nvd.py                 NVD client. Pages every query to exhaustion, because a
                         single-page query truncates silently and returns no error
  ground_truth.py        recovers the CISA ICSMA medical CVE set through NVD
                         (CISA's site blocks automated access; the advisory
                         linkage is recoverable from NVD's own records)
  profile.py             per-CVE attack vector, CWE class, CPE part and severity,
                         and the mechanism breakdown that explains the zero
  metasploit.py          module coverage: offline from the shipped metadata, and
                         live over msfrpcd with a whole-identifier match guard
  exploit_signals.py     the other three signals: KEV, EPSS, NVD exploit tags
  weakness_profile.py    how medical and consumer devices fail, side by side
  timing.py              which channel publishes first, CISA or NVD
  reverse_lookup.py      the reverse question: what medical software does
                         Metasploit target at all?
  figures.py             all three figures, matplotlib, greyscale-safe

run/                     thin entry points: read, call, write, print
  verify_paper_numbers.py  re-derive every number in the paper        (offline)
  check_coverage.py        coverage across the three populations      (offline)
  compare_weaknesses.py    medical vs consumer weakness profiles      (offline)
  analyse_timing.py        advisory-vs-NVD publication lag            (offline)
  reverse_lookup.py        medical modules in the framework           (offline)
  breakdown.py             coverage by device class and CPE part      (offline)
  make_figures.py          coverage and mechanism figures             (offline)
  make_signal_figure.py    the signal-agreement Venn                  (offline)
  analyse_signals.py       KEV, EPSS and NVD exploit tags             (network)
  industrial_comparison.py is the blind spot medical or CPS-wide?     (network)
  reconcile_prior_work.py  compare against prior work's dataset      (network)
  audit_exclusions.py      why each of their 182 CVEs is absent       (network)
  audit_exploit_references.py  exploit-hosting links, tag aside       (network)
  scorer_sensitivity.py    does the scorer's exploit feature bias     (offline)
                           consumer coverage?
  fetch_ground_truth.py    rebuild the ground truth from NVD          (network)
  build_profile.py         rebuild the exploitability profile         (network)
  verify_live.py           re-check coverage against running Metasploit

results/
  cisa_icsma_cves.json                341 CVEs / 138 advisories, Sept 2026 snapshot
  cisa_exploitability_profile.json    attack vector, CWEs, CPE parts, score per CVE
  medical_valid_cves.csv              1,281 medical CVEs, module counts, device class
  consumer_iot_cves.json              the consumer-IoT comparison set
  msf_live_medical.json               live msfrpcd run against both medical sets
  msf_live_consumer.json              the consumer-IoT coverage measurement
  exploit_signals.json                KEV, EPSS and NVD exploit-tag results
  disclosure_timing.json              advisory-vs-NVD lag, per CVE
  metasploit_medical_modules.json     the 8 medical modules in the framework
  weakness_comparison.json            medical vs consumer weakness families
  breakdown.json                      coverage by device class and CPE part
  industrial_comparison.json          the third population: 3,429 industrial ICS
                                      CVEs measured the same way
  cisa_industrial_cves.json           their profiles, from the same CISA extraction
  prior_work_reconciliation.json      overlap with Bracciale et al.'s published
                                      470-CVE dataset, and their threat classes
  prior_work_dataset.csv              their dataset as downloaded
  exclusion_audit.json                per-record reason each of their 182 CVEs
                                      falls outside our extraction: 181 by source
                                      attribution, 1 by a missing ICSMA reference
  exploit_reference_audit.json        exploit-hosting links in the 341 records.
                                      NVD tags none Exploit; one cites Exploit-DB
  scorer_sensitivity.json             consumer coverage with the scorer's exploit
                                      feature removed: 26.0% -> 28.0%
  denominator_check.json              CVEs with a module that were still excluded
                                      as irrelevant, so neither coverage rate is
                                      inflated by the quantity it measures
  coverage.json                       written by run/check_coverage.py

data/msf/modules_metadata_base.json   Metasploit 6.5.3 module index (11 MB)
data/nvd/ground_truth_records.json    the 341 NVD records, as fetched
data/consumer/                        consumer NVD details and the 33
                                      groundings, for the sensitivity check
figures/                              written by the two figure runners
```

## Four measurement details that change the answer

**Metasploit's `cve:` search matches substrings.** Searching `cve:2022-2069`
also returns the module for CVE-2022-20699, and search results carry no
references to check against. `metasploit.live_modules_for` fetches each module's
own reference list and compares whole identifiers. Taking the filter at face
value adds three spurious matches.

**NVD queries truncate silently.** A query matching 115 CVEs returns 25 with no
error. `nvd.page_query` reads `totalResults` and pages to exhaustion.

**The advisory identifier encodes its own date.** `ICSMA-19-190-01` is day 190
of 2019, so the difference against NVD's publication date is computable for every
CVE without scraping CISA. The advisory date is earlier in 286 of 341 cases and
later in none, median 6 days, and 266 differ by no more than 30 days. Advisories
are revised, so a CVE added later inherits the original date: these are
record-date differences, not verified disclosure order.

**The source filter, not the advisory reference, is what limits the ground
truth.** Auditing the 182 CVEs in prior work's dataset that we miss,
`audit_exclusions.py` finds 181 excluded because NVD attributes the record to
another CNA (MITRE, Microsoft, device vendors) and only 1 for a missing ICSMA
reference — and 85 of those 181 do cite an ICSMA advisory. Keying on the
reference instead of the source would recover them.

## Reproducing from scratch

```bash
export NVD_API_KEY=...                 # optional, 10x the rate limit
python run/fetch_ground_truth.py       # CISA ICSMA set, through NVD
python run/build_profile.py            # attack vector / CWE / severity per CVE
python run/analyse_signals.py          # KEV, EPSS, NVD exploit tags
python run/check_coverage.py           # coverage across the three populations
python run/make_figures.py && python run/make_signal_figure.py

msfrpcd -P <password> -S -a 127.0.0.1 -p 55553    # in WSL or on Linux
MSF_RPC_PASSWORD=<password> python run/verify_live.py
```

## Scope and limits

* **The ground truth is a lower bound.** ICSMA is high-precision but partial:
  some medical CVEs sit under general `ICSA-` advisories, some never reach CISA.
  "0 of 341" means none of the CISA-labelled set, not none in existence.
* **Coverage is one framework version at one date** (Metasploit 6.5.3), not a
  stable quantity, and commercial exploit kits are out of scope.
* **Absence of a signal is not absence of risk.** Nearly 40% of the curated set
  is a credential or design failure, which needs no exploit code at all.
* **All NVD data are a September 2026 snapshot.** CISA publishes continuously,
  so `fetch_ground_truth.py` now returns slightly more than 341 CVEs. Use
  `verify_paper_numbers.py` to check the paper; use the fetchers to check the
  method.
* **KEV and EPSS are moving targets.** The catalog only grows and EPSS is
  recomputed daily, so both are reported as measured on **29 September 2026**
  (recorded as `measured_on` in `exploit_signals.json`). `verify_paper_numbers.py`
  checks the shipped values and stays reproducible; `analyse_signals.py` fetches
  current ones and will differ.
* The 1,281-CVE set depends on an automated relevance scorer deciding which
  CVEs are medical; the 0 of 341 does not depend on it at all.
