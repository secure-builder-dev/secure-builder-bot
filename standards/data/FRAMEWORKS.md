> ## ⚠ TODO — one download away from closing the last gap
>
> **What:** the DISA **Application Security and Development STIG** (`APSC-DV-*`). This repo cites it
> 52 times across the aws, azure, android and tactical checklists, and **nothing verifies any of
> them.** It is the only verification gap left.
>
> **Why it is still open:** the agent's network cannot reach `cyber.mil`, `public.cyber.mil`,
> `dl.dod.cyber.mil` or `stigviewer.com` — all blocked by egress policy. An ordinary machine reaches
> them fine. So this needs a human with a browser, once.
>
> **Steps — about five minutes:**
>
> 1. Go to `https://public.cyber.mil/stigs/downloads/` (or `cyber.mil`, or STIG Viewer) and search
>    for **"Application Security and Development"**. Download the ZIP.
> 2. From the repo root, run — no need to unzip it:
>
>    ```
>    make ingest-stig FILE=~/Downloads/U_ASD_V5R3_STIG.zip
>    ```
>
> 3. Run `make verify-citations`. The line that reads `33 of 86 STIG` should become `86 STIG`, and
>    the `NOT COVERED (APSC)` line should disappear.
> 4. Update the ASD STIG row in the table below: fill in the `Verified` column with today's date and
>    the edition you downloaded.
> 5. Commit the new supplied-index file it writes under `standards/data/controls/` — the script
>    prints the exact path — along with this file.
>
> **If it refuses the file:** it will say so and why. A refusal for a CUI marking is the script doing
> its job — read the message before overriding it with `--acknowledge-cui`.
>
> **You cannot forget this.** `make verify-citations` prints the count, the `APSC` prefix and that
> command on every single run until it is done. Delete this box when it is.

---

## About This Document

**Purpose:** The provenance record for every external standard this engine cites. Names the exact edition, where it came from, when it was last verified and how.

**Workflow role:** Sentinel does not read this at gate time. A human reads it when someone asks "which version of that are you working from?", and whoever refreshes a framework updates the row.

**How to fill in:** Add a row when the engine starts citing a new standard. Update `verified` when you re-check one. Never leave `verified` blank — an unverified row is the honest state and should say so.

---

# Frameworks and Editions

**Why this file exists.** On 2026-09-19 an audit found four wrong citations in the security docs.
Three were catalogue errors — `SA-12` and `IR-10` were withdrawn in Rev 5 and cited as live,  <!-- citations: allow -->
`AU-9(2)` carried `AU-9(4)`'s title. The fourth was different in kind: the excessive-agency check
was labelled `LLM08`, which was correct in the **2023** edition of the OWASP LLM Top 10 and wrong in
the **2025** edition, where excessive agency is `LLM06` and `LLM08` is something else entirely.

No script catches that fourth class. The standard did not change — the *numbering* did, underneath
a citation that never named which edition it meant. The defence is a dated, versioned citation, and
this file is where those dates live.

**What a green `make verify-citations` does and does not mean.** It proves every NIST control ID in
the documents exists in the pinned catalogue and has not been withdrawn. It does **not** prove the
cited control is the *right* one for the check beside it — `AC-3` where `AC-6` belonged resolves
perfectly. That judgment is human and is made at the governance review when a checklist item
changes. Do not read a green run as a validated mapping.

---

## Machine-verified

Cited IDs are checked mechanically on every push by `make verify-citations`, against a vendored
index. Vendored for **determinism, not connectivity** — the engine develops low and ships high, so
it can reach the internet freely. A gate verdict must be reproducible: two runs over the same commit
have to reach the same answer, and a gate-log row has to point at something re-derivable months
later. A catalogue fetched mid-run cannot promise that. So refreshing is a deliberate act that lands
in a diff, and every verdict is anchored to a named revision.

The rule of thumb this sets: **live fetch for reporting, vendored copy for verdicts.** Checking
whether a newer revision exists is reporting and can hit the network any time. Deciding whether a
citation is valid is a verdict and reads the committed copy.

| Framework | Edition | Source | Retrieved | Verified how |
|---|---|---|---|---|
| OWASP Top 10 (web) | **2025** (`2025` list vendored alongside `2021` for migration checks) | [OWASP/Top10](https://github.com/OWASP/Top10) — `<edition>/mkdocs.yml` nav, the project's own ordered list, commit `66ebc479` | 2026-09-19 | `make verify-citations` against `controls/owasp-index.json` — a stale identifier is a **hard failure**, not advisory |
| OWASP Top 10 for LLM Applications | **2025** | [www-project-top-10-for-large-language-model-applications](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications) — `2_0_vulns/` filenames, commit `99f43955` | 2026-09-19 | same checker; `selftest.sh` carries a regression test for the LLM08→LLM06 renumbering |
| DISA STIGs — OS and platform | RHEL 8 v2r8 · RHEL 9 v2r9 · RHEL 10 v1r2 · Oracle Linux 7/8/9 · SLES 12/15 · SLE Micro 5 · Ubuntu 22.04 v2r8 · Ubuntu 24.04 v1r6 · OpenShift 4 v2r6 · RHCOS 4 v2r6 · Application v2r1 / Container v1r3 / OS v3r2 / DNS v2r2 SRGs | **[ComplianceAsCode/content](https://github.com/ComplianceAsCode/content)** redistributing the DISA XCCDF manuals — **not DISA directly** | 2026-09-19 | `make verify-citations` against `controls/stig-index.json` (**4,010 rules, 18 STIGs**). Only ids whose platform prefix the index carries are adjudicated; the rest are counted and named in the run output, never left silent. |
| OWASP MASVS | **v2** — release `v2.1.0`, catalogue taken from commit `6df8fc412628` | [OWASP/masvs](https://github.com/OWASP/masvs) — `OWASP_MASVS.yaml`, the project's own machine-readable catalogue (24 controls, 8 groups) | 2026-09-19 | `make verify-citations` against `controls/masvs-index.json`. An unknown `MASVS-*` id is a **hard failure**, and so is a `MSTG-*` id — that is MASVS v1 numbering, which v2 renumbered wholesale. |
| NIST SP and FIPS — **revision currency** | SP 800-163 **Rev 1** · SP 800-124 **Rev 2** · SP 800-157 · FIPS 140-3 · FIPS 199 · FIPS 200 — every one confirmed the current published revision on 2026-09-19 | [usnistgov/NIST-Tech-Pubs](https://github.com/usnistgov/NIST-Tech-Pubs) — NIST's own publication metadata; `bib/` filenames encode series, number, revision and draft stage | 2026-09-19 | `make verify-citations` against `controls/nist-pubs-index.json` (1,679 publications). A revision that was never published is a **hard failure**; a revision NIST has since superseded is **reported on every run**, not failed — adopting one is a decision. |
| NIST SP 800-53 | **Rev 5.2.0** (catalogue last modified 2026-05-11) | [usnistgov/oscal-content](https://github.com/usnistgov/oscal-content) — `NIST_SP-800-53_rev5_catalog.json`, SHA-256 `01f37cf90ea99d92…` | 2026-09-19 | `make verify-citations` against `controls/nist-800-53r5-index.json` (1,196 controls, 182 withdrawn). Regenerate with `standards/scripts/build-control-index.py`. |

Note the revision: the documents say "Rev 5 (2020)", and the current catalogue is **5.2.0**. The
control IDs the engine cites are stable across those patch revisions, but the wording is not — treat
the "(2020)" in document headers as the revision line, not the patch level.

Note the MASVS pin: `OWASP_MASVS.yaml` is maintained on the default branch and its own
`metadata.version` is a placeholder (`vx.x.x`), while the newest release tag (`v2.1.0`) ships the
same controls as per-control markdown and no machine-readable catalogue. So the reproducible pin is
the **commit**, not the tag. Verified by hand on 2026-09-19 that the id set in the vendored index
matches the `v2.1.0` release's `controls/` directory exactly; the builder re-checks the YAML against
that directory on every run and fails if they disagree.

---

## Verified by reading, not by script

No machine-readable catalogue exists for these, so currency depends on the `verified` date. This
table used to hold six rows. Four of them — SP 800-163, SP 800-124, SP 800-157 and the FIPS set —
moved up into **Machine-verified** on 2026-09-19 once NIST's own publication metadata turned out to
be on GitHub. What is left is genuinely unreachable, not merely unautomated, and each row says which.

| Framework | Edition | Verified | State |
|---|---|---|---|
| DISA Mobile Application STIG | n/a | 2026-09-19 | **Out of scope — a boundary, not a gap.** The STIG is CUI-marked and published behind DoD PKI at `cyber.mil`; these are not CUI workstations, so it cannot enter this repository by any route, and no redistributor carries it. The Android track is grounded in **OWASP MASVS v2** instead (machine-verified, row above). Where a formal assessment needs the mobile STIG, that is a CAC holder's task on a CUI workstation, outside this engine. |
| DISA Application Security and Development STIG | **V5R3** | — | **52 `APSC-DV-*` citations (16 distinct ids) across the aws, azure, android and tactical checklists, none adjudicated yet — but one command away.** The Application SRG v2r1 *is* in the index; it is a different namespace (`SRG-APP-*`) and does not cover them, and `APSC-DV` appears nowhere in ComplianceAsCode. Download the STIG and run **`make ingest-stig FILE=<the .zip>`** — the parser is the same one proven on 4,010 rules, and the file's SHA-256 is recorded. Until then every run names the count and the `APSC` prefix, so the gap is stated rather than mistaken for coverage. |
| DoD Cloud Computing SRG | **v1r4** | — | Not re-verified since 2026-05-01. DISA publishes it at `public.cyber.mil`; no machine-readable list exists and the host is unreachable from this environment. |
| CNSSI 1253 · ICD 503 · CNSSP-15 · ICD 710 (CAPCO) | current | — | Cited by name only, in the IL6 block. No identifiers to drift and no public catalogue; currency is an organisational-channel question. |

---

## Applied: OWASP Top 10 2021 → 2025 migration

Applied 2026-09-19 against the primary source — OWASP's own `2025/mkdocs.yml` nav, obtained by
shallow-cloning [OWASP/Top10](https://github.com/OWASP/Top10). The earlier draft of this table was
built from secondary sources and marked unconfirmed; every row it guessed turned out correct, but
it was not transcribed until the publisher's own file said so.

| 2021 identifier | 2025 identifier |
|---|---|
| A01 Broken Access Control | A01 Broken Access Control — SSRF folded in |  <!-- citations: allow -->
| A02 Cryptographic Failures | **A04** Cryptographic Failures |  <!-- citations: allow -->
| A03 Injection | **A05** Injection |  <!-- citations: allow -->
| A05 Security Misconfiguration | **A02** Security Misconfiguration |  <!-- citations: allow -->
| A06 Vulnerable and Outdated Components | **A03** Software Supply Chain Failures |  <!-- citations: allow -->
| A07 Identification and Authentication Failures | A07 **Authentication Failures** |  <!-- citations: allow -->
| A09 Security Logging and Monitoring Failures | A09 Security Logging and **Alerting** Failures |  <!-- citations: allow -->

Two consequences carried into `CONTROLS-MAPPING.md` Known Gaps rather than silently absorbed:
SSRF no longer stands alone under 2025, so that open gap now sits inside a category the engine
otherwise covers well — easier to miss, not less real. And **A10:2025 Mishandling of Exceptional
Conditions** is new with no mapped check; the global error-handler row is the obvious candidate,
but that is a mapping judgment and stays a human call.

---

## Open findings from the first STIG index run

**The ≥80% STIG-id rule was replaced — it was unmeetable everywhere.** Each provider checklist
carried the line *"Murat verification: STIG IDs present on ≥ 80% of items"*. Across the four, 61
items are `[Framework-derived]` and 62 STIG-id citations exist. Counting what each would hold showed
the rule was unmeetable even on tactical — 25 ids against 60 items. Replaced 2026-09-19: tactical
requires a published id on every **Section 1 (OS Hardening)** item and verifies it mechanically; the
other three tracks require every item to name a published id **or** its derivation source, with no
percentage, because no platform STIG exists for their surface.

**The Android checklist's grounding was rebuilt on MASVS — closed 2026-09-19.** It had no verifiable
mobile citation at all: its `APSC-DV-*` ids come from a STIG behind DoD PKI, and the Mobile
Application STIG it named cannot enter this repository. Every one of its 52 items now also names an
**OWASP MASVS v2** control, and `make verify-citations` resolves all of them against the pinned
catalogue — 60 citations in that file, 69 across the repo. Nine items carry `—` where no MASVS
control fits (APK distribution channel, ATAK version floor, WatchTower handoff, backend SQLi):
blank rather than guessed, the same rule the OWASP column follows.

**Two citations remain stale; three were re-derived.** The tactical checklist dual-cites RHEL 8 and
Ubuntu, and the Ubuntu column pointed at 20.04 — end of life, dropped upstream. Seven Section 1 rows
now carry a published **Ubuntu 22.04** equivalent, applied only where the indexed title states the
same requirement (`UBTU-22-211000` vendor-supported release, `UBTU-22-255050` FIPS SSH ciphers,
`UBTU-22-611060` blank passwords, `UBTU-22-411010` root login, `UBTU-22-412010` logon delay,
`UBTU-22-654235` privileged-activity audit, `UBTU-22-411035` 35-day inactivity — which matches the
threshold exactly). Two rows keep a **STALE CITATION** note because no published rule clearly
matches: `UBTU-20-010222` (unsuccessful file-access auditing — the nearest 22.04 rule is scoped to  <!-- citations: allow -->
`/etc/sudoers`) and `RHEL-08-020040` (absent from RHEL 8 v2r8 entirely). Those need STIG Viewer  <!-- citations: allow -->
access, not a better guess.

**Forty-eight PostgreSQL citations were retired.** `PGS9-00-*` ids across the aws, azure and
tactical checklists referenced the PostgreSQL 9 STIG, end of life since 2021 and carried by no
redistributor, so nothing could ever verify them. The requirement text was sound and is unchanged;
the identifiers are retained as `(was PGS9-…)` historical pointers and each section says why.
Refreshing them against a current PostgreSQL STIG needs STIG Viewer access.

---

## Two defects found on 2026-09-19, after the MASVS work

**The STIG index silently dropped every SRG.** `build-stig-index.py` matched one ID shape,
`[A-Z0-9]{4}-\d{2}-\d{6}`. The SRGs use `SRG-APP-000001-AS-000001` and OpenShift/RHCOS use
`CNTR-OS-000010`, so 862 rules were parsed and thrown away without a word — while the row above and
the script's own docstring both claimed the SRGs were carried. Fixed: the pattern now covers the ID
shapes DISA actually publishes, censused across every manual ComplianceAsCode redistributes. The
index went from 3,329 rules / 12 STIGs to **4,010 / 18**. The browser STIGs stay out on purpose:
`DTBF003` and `DTBC-0001` need a pattern loose enough to also match prose like "RFC5280", and the
engine cites none of them.

**Fifty-two `APSC-DV-*` citations were invisible, not merely unverified.** The citation-side pattern
had the same defect, so it could not match `APSC-DV-002000` at all. They were neither adjudicated
nor counted as uncovered, and the summary line read `24 STIG citations resolve` — which a reader
would fairly take to mean all of them. It now reads `24 of 76`, and the uncovered count and prefix
print on every run rather than only under `--advisory`.

Both were defects in the STIG work committed earlier the same day. They are recorded here rather
than quietly fixed because a provenance file that hides its own corrections is worth less than one
that does not.

**The citation checker was not reading its own provenance record.** The file list is a glob, and
`standards/data/**/*.md` does not match a file sitting directly under `standards/data/` — git's
`**/` requires an intermediate directory. So `FRAMEWORKS.md` and `README.md` were never scanned.
Adding `standards/data/*.md` brought this file into scope and it immediately reported nine
citations: the withdrawn `SA-12` and `IR-10` it discusses, <!-- citations: allow --> the 2021 identifiers in the migration
table, and the two known-stale STIG ids. All nine are deliberate mentions in a document whose
subject is stale citations, so they now carry the `citations: allow` marker. One was a true checker
false positive — `LLM06` followed by prose read as a title claim — and was fixed by rewording rather
than by marking, because a marker there would have hidden a real weakness.

**What the ASD STIG needed, and what was built instead of a fetcher.** `cyber.mil`,
`public.cyber.mil`, `dl.dod.cyber.mil`, `stigviewer.com` and `csrc.nist.gov` are all denied by this
environment's egress policy, which permits GitHub and the package registries only. That is an
environment setting, not a property of the standard — an ordinary network reaches all of them.

Hardcoding a recalled download URL would have been a guess, and the missing piece was never the
parser: `build-stig-index.py` already reads DISA's XCCDF and is proven on 4,010 rules across 18
STIGs. What was missing was delivery. So `make ingest-stig FILE=<the .zip you downloaded>` takes the
file from whoever can reach the download and does every part that can be checked mechanically —
unzip, prefer the Manual rendering, parse with that same proven code, and record the file's name and
**SHA-256**. That chain is stronger than the redistributed content, not weaker: "this exact file,
here is its hash" beats "a third party says this is what DISA published."

Two design points worth knowing. Supplied content goes to `controls/stig-index-supplied.json`, never
into `stig-index.json`, because `refresh-frameworks --adopt` regenerates the latter from
ComplianceAsCode and would silently delete it — asserted in the selftest. And the script **refuses a
document whose own front matter carries a control marking** (`CUI`, `NOFORN`, a restricted
distribution statement), which is the rule that keeps the Mobile Application STIG out; it reads the
Benchmark's front matter only, never rule bodies, because real STIG guidance says things like
"marking data as classified or FOUO" and failing on that would make the check useless. Override with
`--acknowledge-cui` only after determining the marking does not apply.

---

## Refreshing a framework

**`make refresh-frameworks`** refreshes all four machine-verified sources in one run: the NIST
800-53 OSCAL catalogue, both OWASP Top 10 lists, the DISA STIGs via ComplianceAsCode, and OWASP
MASVS. For NIST it reports the delta **scoped to the controls this repo actually cites** — usually a
far shorter list than "N controls changed". It writes nothing unless asked. Only NIST is pinned;
OWASP and MASVS are not accreditation baselines, so for those newest is simply correct.

| Exit | Meaning |
|---|---|
| 0 | vendored index matches what is published, or `--adopt` succeeded, or `OFFLINE=1` |
| 3 | a newer revision exists. A signal, not a failure — the scheduled CI job opens a PR |
| 1 | a source was unreachable. **An error, not a fallback** — silently using the stale copy is what let "unverified" exist |

`OFFLINE=1` skips the fetch and says so in the output. That is the honest disconnected run, not a
silent degradation. It also serves the air-gapped sibling engine, which reads the same committed
index through the same code path.

It runs at three entry points so nobody has to remember it: `make onboard` (a new project is never
set up against stale references — unreachable fails onboarding), after `make sync-engine`, and
weekly in this repository's own CI, which opens a PR carrying the delta.

**Adoption is deliberate.** `--adopt` rebuilds the index; the pin in `project.config.yaml`
(`NIST_CATALOG_PIN`) records the revision your ATO names. The job never adopts on its own, because
checking against a baseline your authorizing official has not approved is a worse failure than being
a revision behind — it is invisible.

For a framework with no fetcher yet:

1. Retrieve the new edition. For NIST, run `build-control-index.py` against the OSCAL catalogue and
   commit the regenerated index — the diff shows exactly which controls changed status.
2. Run `make verify-citations` and fix what it reports. A newly withdrawn control becomes a finding
   in every document that cites it.
3. Run `make verify-citations --advisory` and reconcile title drift.
4. For a framework with no catalogue, re-read the published list and check the numbering against
   every place the engine cites it. Numbering is the thing that moves.
5. Update the row here: edition, source, date, and who verified it.
6. Where the refresh changes a gate checklist item, that is a rulebook change — its own commit, and a
   human reads the diff (`engine/GOVERNANCE.md`).

`make gate-state` prints the age of the NIST index at every gate. It reports; it does not block.
A stale provenance record leaves no other check verifying nothing, so under ADR-036 it is a finding
a human acts on, not a gate stop.
