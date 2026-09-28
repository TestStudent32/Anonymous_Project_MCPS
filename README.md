# Are medical-device vulnerabilities weaponised?

Artifact for the paper. It measures how many known medical-device CVEs carry a
Metasploit module, and explains why the answer is so close to zero.

**Headline result**

| Population | With a Metasploit module |
|---|---|
| Consumer IoT (same pipeline) | 54 of 208 — **26%** |
| Medical, our valid set | 15 of 1,281 — **1.2%** |
| Medical, CISA-curated | **0 of 341** |

The zero is structural, not incidental. Of the 341 CISA-curated CVEs only 50%
are network-reachable, and 39% are credential, access-control or cleartext
design failures where exploitation means using a documented default rather than
delivering a payload. Network-reachable **and** an implementation bug leaves
**102 (30%)** as the only plausible module targets. Severity does not explain
it either: 50% of the set is high or critical.

## Verify the paper in one command

No API key, no network, no Metasploit install. Every number in the paper is
re-derived from the data in `results/` and checked against what the paper
claims:

```bash
pip install -r requirements.txt
python run/verify_paper_numbers.py        # expect: PASS 22   FAIL 0
```

## What each file does

```
iomt_exploit/            the logic, importable and testable
  nvd.py                 NVD client. Pages every query to exhaustion, because a
                         single-page query truncates silently and returns no error
  ground_truth.py        recovers the CISA ICSMA medical CVE set through NVD
                         (CISA's site blocks automated access; the advisory
                         linkage is recoverable from NVD's own records)
  profile.py             per-CVE attack vector, CWE class, CPE part and severity,
                         plus the mechanism breakdown that explains the zero
  metasploit.py          module coverage. Offline from the shipped metadata, and
                         live over msfrpcd with a whole-identifier match guard
  figures.py             both figures, matplotlib only, greyscale-safe

run/                     thin entry points: read, call, write, print
  verify_paper_numbers.py  re-derive every number in the paper        (offline)
  check_coverage.py        coverage across the three populations      (offline)
  make_figures.py          regenerate both figures                    (offline)
  fetch_ground_truth.py    rebuild the ground truth from NVD          (network)
  build_profile.py         rebuild the exploitability profile         (network)
  verify_live.py           re-check coverage against running Metasploit

results/
  cisa_icsma_cves.json                341 CVEs / 138 advisories, Sept 2026 snapshot
  cisa_exploitability_profile.json    attack vector, CWEs, CPE parts, score per CVE
  medical_valid_cves.csv              1,281 valid medical CVEs with module counts
  msf_live_medical.json               live msfrpcd run against both medical sets
  msf_live_consumer.json              the consumer-IoT comparison point
  coverage.json                       written by run/check_coverage.py

data/msf/modules_metadata_base.json   Metasploit 6.5.3 module index (11 MB)
figures/                              written by run/make_figures.py
```

## Two measurement details that change the answer

**Metasploit's `cve:` search matches substrings.** Searching `cve:2022-2069`
also returns the module for CVE-2022-20699, and search results carry no
references to check against. `metasploit.live_modules_for` therefore fetches
each module's own reference list and compares whole identifiers. Taking the
filter at face value adds three spurious matches to the medical set.

**NVD queries truncate silently.** A query matching 115 CVEs returns 25 with no
error. `nvd.page_query` reads `totalResults` and pages to exhaustion.

## Reproducing from scratch

```bash
export NVD_API_KEY=...                 # optional, 10x the rate limit
python run/fetch_ground_truth.py       # CISA ICSMA set, through NVD
python run/build_profile.py            # attack vector / CWE / severity per CVE
python run/check_coverage.py           # coverage across the three populations
python run/make_figures.py             # both figures

msfrpcd -P <password> -S -a 127.0.0.1 -p 55553    # in WSL or on Linux
MSF_RPC_PASSWORD=<password> python run/verify_live.py
```

## Scope and limits

* **The ground truth is a lower bound.** ICSMA is high-precision but partial:
  some medical CVEs sit under general `ICSA-` advisories, some never reach CISA.
  So "0 of 341" means none of the CISA-labelled set, not none in existence.
* **Coverage is one framework version at one date** (Metasploit 6.5.3), not a
  stable quantity.
* **We measure public weaponisation, not exploitability.** No module is not
  proof that a flaw cannot be exploited.
* **All NVD data are a September 2026 snapshot.** CISA publishes continuously,
  so re-running `fetch_ground_truth.py` returns slightly more than 341 CVEs.
  Use `verify_paper_numbers.py` to check the paper; use the fetchers to check
  the method.
* The 1.2% figure depends on our relevance scorer deciding which CVEs are
  medical; the 0 of 341 does not depend on it at all.
