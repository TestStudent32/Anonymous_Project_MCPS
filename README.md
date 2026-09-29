# Are medical-device vulnerabilities weaponised?

Artifact for the paper. It asks every public exploitation signal the same
question about the same medical CVEs, and finds that none of them sees these
devices at all.

**The four signals, on 341 CVEs that CISA has published a medical advisory for**

| Signal | What it means | Result |
|---|---|---|
| Metasploit module | public exploit code exists | **0 of 341** |
| CISA KEV | exploitation observed in the wild | **0 of 341** |
| NVD `Exploit` reference tag | NVD links exploit material | **0 of 341** |
| EPSS | predicted exploitation probability | median **0.005**, max 0.128 |

For comparison, 26% of consumer-IoT CVEs have a Metasploit module on the same
pipeline, and the 15 medical CVEs that do have one score a median EPSS of 0.90.

**This is not evidence that the devices are safe.** KEV requires exploitation to
be detected, attributed and reported, which rarely happens for hospital
equipment, and EPSS is trained on signals a niche device flaw cannot produce.
Agreement between the signals shows the ecosystem has no visibility into these
devices — which is why triage for them cannot be driven by any of these signals.

**Why the gap exists.** Medical CVEs are 3.0x more likely than consumer-IoT ones
to be a credential or design failure (38.8% vs 13.0%), and consumer CVEs 3.2x
more likely to be an implementation bug (51.5% vs 16.2%) — which is what an
exploit module encodes. Only 50% of the curated set is network-reachable, and
excluding credential and design failures leaves 102 CVEs (30%) a module could
plausibly target.

## Verify the paper in one command

No API key, no network, no Metasploit install:

```bash
pip install -r requirements.txt
python run/verify_paper_numbers.py        # expect: PASS 99   FAIL 0
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
  denominator_check.json              CVEs with a module that were still excluded
                                      as irrelevant, so neither coverage rate is
                                      inflated by the quantity it measures
  coverage.json                       written by run/check_coverage.py

data/msf/modules_metadata_base.json   Metasploit 6.5.3 module index (11 MB)
figures/                              written by the two figure runners
```

## Three measurement details that change the answer

**Metasploit's `cve:` search matches substrings.** Searching `cve:2022-2069`
also returns the module for CVE-2022-20699, and search results carry no
references to check against. `metasploit.live_modules_for` fetches each module's
own reference list and compares whole identifiers. Taking the filter at face
value adds three spurious matches.

**NVD queries truncate silently.** A query matching 115 CVEs returns 25 with no
error. `nvd.page_query` reads `totalResults` and pages to exhaustion.

**The advisory identifier encodes its own date.** `ICSMA-19-190-01` is day 190
of 2019, so the publication lag against NVD is computable for every CVE without
scraping CISA. CISA publishes first in 286 of 341 cases; NVD never does.

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
