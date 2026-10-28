# Spec: standards

Module `standards` of the capability map. Status: built on `wip/standards`; the decisions below were
taken during the build and are confirmed by the human who merges it.

## Objective

`standards` is what the gates cite. It holds the vendored NIST SP 800-53 Rev 5 catalog and its
Moderate and High baselines, the DISA STIG index, the OWASP Top 10 and LLM Top 10 lists, OWASP MASVS
and NIST's publication list, as the publishers published them, pinned to a known revision; the
builders that wrote each index from its source; the verifier that holds every document in the
repository to those indexes; the versions a receipt records; and the weekly refresh that keeps the
vendored copies current and refuses a revision that would break a citation. It depends on nothing
but the standard library. It is not a gate: core calls `versions()` for the receipt, and sentinel
will read the catalog, the baselines and the checklists.

User stories, from the PRD:

- As an assessor, I see in every receipt which catalog version the run resolved against, and I can
  trust that a control id in the checklist is a real, current control (§ Compliance profiles).
- As a contributor, I cite a control in a checklist item and the citation verifier runs on my PR; an
  id that does not exist or was withdrawn cannot merge (§ Open source).
- As the maintainer, I never download a standard: a weekly workflow in the bot's own repository
  fetches each upstream, regenerates what changed and opens a PR naming controls added, withdrawn
  or renamed and STIG rules that moved; nothing is ever scheduled in a user's repository (§ Staying
  current).

## Tech Stack

- Python 3.12, standard library only. No new dependency: `docs/architecture/DEPENDENCY_POLICY.md`
  § 4A is unchanged.
- Bash 5 for `standards/run`, `verify-citations.sh` (a wrapper), `refresh-frameworks.sh` (the
  manual, pin-respecting refresh) and the script self-test.
- `curl` and `git` for the online refresh, as the shell refresh always used them (they honour a
  runner's proxy and an air-gapped mirror).

## Commands

```
Verify every tracked document:   make verify-citations            (= standards/run verify --tracked)
Verify given files:              standards/run verify [--advisory] [--list-cited] [--data DIR] FILE...
Receipt versions:                standards/run versions
Look up controls:                standards/run catalog AC-2 SC-7(3)
Weekly refresh:                  make refresh-standards ARGS="--dry-run"      (= standards/run refresh)
Offline, from fixtures:          standards/run refresh --dry-run --offline standards/tests/fixtures/upstream-unchanged
Manual refresh with the pin:     make refresh-frameworks [ARGS=--adopt]  [OFFLINE=1]
A STIG nobody redistributes:     make ingest-stig FILE=~/Downloads/U_ASD_V5R3_STIG.zip
Regenerate the offline fixtures: python3 standards/tests/fixtures/make-upstream.py
Tests:                           make test        (pytest, every module's package under coverage)
Script self-test:                standards/tests/standards-selftest.sh   (part of make gate-selftest)
```

## Project Structure

```
standards/
  run                          → standards/run, the command line (PYTHONPATH=standards python3 -m securebuilderbot_standards)
  securebuilderbot_standards/
    __init__.py                → the public names; no GATE: standards is not a gate
    data.py                    → the indexes as objects: Control, StigRule, OwaspLists, Masvs, NistPub; versions()
    citations.py               → Citation, Verifier, verify_citations(); the six decisions (CM-30, CM-32..36); DOCUMENTS
    refresh.py                 → the weekly refresh; refuse_broken_citations (CM-31); the changelog
    __main__.py                → verify | versions | catalog | refresh
  data/                        ← engine/security/, moved with its history
    controls/*.json            → the six vendored indexes (each records its source, date and generator)
    controls/*.md              → IL4 baseline, IL6 delta, the controls mapping, CDS guidance
    checklists/                → IL6.md, android.md, tactical.md (the gate agent reads them by profile)
    providers/                 → aws, azure, android, tactical implementation guides and STIG checklists
    FRAMEWORKS.md, README.md   → the provenance record and the index of the tree
  scripts/                     ← engine/scripts/gate/{build-*,ingest-stig,refresh-frameworks,verify-citations}
    build-control-index.py  build-baselines-index.py  build-stig-index.py  build-owasp-index.py
    build-masvs-index.py  build-nistpubs-index.py  ingest-stig.py  refresh-frameworks.sh  verify-citations.sh
  tests/
    test_catalog.py  test_citations.py  test_cli.py  test_refresh.py
    test_build_baselines_index.py  test_stig_xml.py      ← core/tests/
    standards-selftest.sh      → the seven sections that lived in engine/scripts/gate/selftest.sh
    conftest.py  smallindex.py → a small index set shaped like the self-test's fixtures
    fixtures/make-upstream.py  → generates the three offline refresh fixtures from the vendored indexes
    fixtures/upstream-unchanged/  upstream-added-control/  upstream-withdrawn-cited/
  CHANGELOG.md                 → written by the refresh when an index changes (not present until the first change)
.github/workflows/refresh-standards.yml   → the one scheduled thing the bot runs, in its own repository
```

Nothing of the module remains under `engine/`.

## Interface

```python
# the indexes as objects; data_dir defaults to standards/data/controls
catalog(data_dir=None) -> dict[str, Control]          # Control(id, title, family, in_moderate, in_high, withdrawn, into)
baseline("moderate" | "high", data_dir=None) -> frozenset[str]
stigs(data_dir=None) -> dict[str, StigRule]           # StigRule(id, title, severity, benchmark, version, supplied)
owasp(data_dir=None) -> OwaspLists | None             # web_edition, llm_edition, web, llm, editions
masvs(data_dir=None) -> Masvs | None                  # release, controls, groups
nist_pubs(data_dir=None) -> dict[str, NistPub]        # NistPub(id, revisions, latest, drafts)
versions(data_dir=None) -> dict                       # catalog, baselines_retrieved, stig_index, owasp, owasp_llm, masvs, nist_pubs

# the verifier
verify_citations(text, *, path="<text>", data_dir=None) -> list[Citation]
    # Citation(id, kind: nist|stig|owasp|masvs|nistpub, ok, reason, status, path, line, detail)
verify_files(paths, data_dir=None) -> (Verifier, list[Citation])
render_report(verifier, citations, advisory=False) -> (text, exit_code)   # the verify-citations output
tracked_documents(repo=".") -> list[str]              # DOCUMENTS, as git lists them

# the refresh
refresh(data_dir=None, offline=None, dry_run=False, docs=None, out=sys.stdout, today=None) -> int
refuse_broken_citations(old_controls, new_controls, docs: dict[path, text]) -> list[Broken]
```

Rules the verifier applies, unchanged from `verify-citations.sh` and now each a tested decision:
an unknown or withdrawn NIST id fails (`is_active_control`, CM-30); an OWASP id whose written
title is not the title it carries in the pinned edition fails and names the right id
(`owasp_title_matches`, CM-32); a STIG id on a platform the index carries that is not in it fails,
one on a platform it does not carry is reported as not covered (`stig_rule_known`, CM-33); an
unknown MASVS id or `MSTG-*` v1 numbering fails (`masvs_id_current`, CM-34); a NIST SP or FIPS
revision never published fails, a superseded one is reported (`pub_revision_published`, CM-35); a
line carrying the allow marker is exempt, and only that line (`line_is_exempt`, CM-36). A `(was X)`
pointer is history, not a citation, for every kind. The manifest's own `CM-nn` row ids are not NIST
controls (three deterministic tells, as before).

Exit codes, every command: 0 ok, 1 refused, 2 could not run. `refresh` adds 3: something changed
(written, or reported under `--dry-run`).

The receipt: `receipt.json` gains a top-level `"standards": versions()` section, through one guarded
import in `core/securebuilderbot_core/runner.py:standards_versions` (None when the module is not
installed, so the key is never silently absent). `receipt.md` does not render it yet.

## The refresh

Each vendored index records its source. The refresh fetches every one (the catalog and the two
baseline profiles from the URLs the indexes record; the OWASP, STIG, MASVS and NIST-publication
repositories by shallow clone), rebuilds the index with the builder that wrote it, compares
`controls` / `moderate`+`high` / the current OWASP editions / `rules` / `controls` / `pubs` with
the committed copy, and when something moved writes the new index atomically and prepends a
`standards/CHANGELOG.md` entry naming controls added, withdrawn (with what they were incorporated
into), reinstated, renamed or removed, baseline membership changes, STIG rules added and removed
and benchmarks that changed, OWASP titles that moved, MASVS controls added or removed, and NIST
publications whose latest revision changed. `--dry-run` reports and writes nothing. `--offline DIR`
reads the upstreams from a directory; a source absent from DIR is said to be not provided, never
read as current.

The refusal (CM-31): before anything is adopted, every tracked document is judged against the old
catalog and the new one; a citation that resolves today and would not under the new catalog
(withdrawn, or removed) refuses the whole refresh: nothing under `data/` changes, the changelog
records the refusal with each item (control, what became of it, file:line), and the exit is 1. The
workflow then fails the run and opens the PR carrying that record, which is how "the PR says which
item" is met: the human re-cites, re-runs, and the next refresh adopts.

The workflow `.github/workflows/refresh-standards.yml` runs weekly and on dispatch with
`contents: write, pull-requests: write`, installs what `make check-task` needs, runs the refresh,
runs `make check-task` on a changed tree, and opens one PR per branch-date with the changelog
diff as its body (a second run the same day finds the open PR and stops). Its header says it is the
one scheduled thing the bot runs, in its own repository, never in a user's.

## Testing Strategy

- pytest under `standards/tests/`: the read API against the vendored indexes and a small index set;
  every verifier rule, both ways; the CLI's exit codes and output; the refresh against three
  committed offline fixtures (criterion 3) and, for the git-backed upstreams, temporary repositories
  built in `tmp_path`. No network anywhere.
- The offline fixtures are generated from the vendored indexes by `make-upstream.py`: a minimal
  OSCAL catalog that carries exactly what the builders read regenerates the vendored index byte for
  byte in `controls`, which is what makes "nothing to do" provable against the real data.
- `standards-selftest.sh` replays the seven engine self-test sections (55 assertions) against the
  wrapper, inside a throwaway repository with its own indexes, so the wrapper is proven to read the
  repository it runs in.
- `make mutate-controls`: every one of CM-30..36 broken on purpose turns the suite red.

## Boundaries

- **Always:** red test first; `make check-fast` before every commit; the indexes are regenerated by
  their builders, never hand-edited (the `_generator` path rename in this epic is the one exception,
  a provenance correction); a refusal writes nothing under `data/`; every string a builder reads
  from a download is untrusted (XCCDF is parsed with DTDs refused, as before).
- **Ask first:** a new upstream source; adopting a catalog revision by hand; changing `DOCUMENTS`;
  editing `engine/SENTINEL-CHECKLIST.md` or the gate agent beyond a path rename.
- **Never:** a network call from the verifier or from any test; a STIG a publisher marks as
  controlled; naming the platform the engine came from; a suppression comment; a schedule in a
  user's repository.

## Success Criteria

1. `make verify-citations` reports the same counts from the new location as before the move.
   **Verified** at the move commit (`962b57e`): 640 NIST + 27 OWASP + 33 of 84 STIG + 69 MASVS +
   127 NIST-pub, identical to the run on `epic/core` before the move (the brief's 636/128 were
   measured at an earlier commit). At the branch head the count is 649 NIST + 27 OWASP + 33 of 84
   STIG + 69 MASVS + 127 NIST-pub: enhancement citations are now judged (see Decisions), eleven wrong
   ones were corrected and eight withdrawn-enhancement rows are exempt, the two `IR-9(1–4)` ranges
   expand to their enhancements, and the seven manifest rows cite the controls they serve.
2. `catalog()["AC-2"]` has its title and is in both baselines; `len(baseline("moderate")) == 287`,
   `len(baseline("high")) == 370`; `verify_citations("AC-2 and AC-99 and SC-7(99)")` marks the last
   two not ok with reasons. **Verified** by `test_catalog.py` and `test_citations.py`
   (`test_the_spec_example_marks_the_last_two_not_ok`).
3. `standards/run refresh --dry-run --offline standards/tests/fixtures/upstream-unchanged` reports
   nothing to do (exit 0); `upstream-added-control` reports `added: AC-99` and, without `--dry-run`,
   regenerates the index (catalog 5.2.1) and writes the changelog line; `upstream-withdrawn-cited`
   exits 1 naming AC-3, what it was incorporated into, and the file:line that cites it.
   **Verified** by `test_refresh.py` through the function and through the CLI. The withdrawn
   control is AC-3 rather than one `engine/SENTINEL-CHECKLIST.md` cites, because that file carries
   no NIST ids in this repository (its items cite through `CONTROLS-MAPPING.md`); AC-3 is cited by
   the mapping, the gate agent and six other tracked documents.
4. `core/run run` receipt carries `standards.catalog == "5.2.0"`. **Verified** by
   `core/tests/test_runner.py::test_receipt_carries_the_versions_of_the_vendored_standards`.
5. `engine/security/` and the moved scripts no longer exist under `engine/`; `make check-task`,
   `make check-docs`, `make gate-selftest` green; `make mutate-controls` proves every row.
   **Verified** by running each at the branch head; the output is in the handback.

## Decisions taken during the build

- **One implementation of the verifier.** The Python heredoc inside `verify-citations.sh` became
  `citations.py`; the script keeps the document list's intent and hands `--tracked` to the package.
  Porting it found that the shell pattern's trailing `\b` never matched after a closing parenthesis,
  so every enhancement citation followed by punctuation or a line end (`SR-4(3)`, `IA-2(1)`) was
  judged as its base control, and `IR-9(1–4)` was not judged at all. The pattern now ends in a
  lookahead, a range names each enhancement, and the eleven wrong citations this exposed in the
  vendored documents are corrected: three `IA-2(1)(2)` are `IA-2(1), IA-2(2)`; eight Rev 4
  enhancements withdrawn in Rev 5 in `IL6-delta.md` say so and name their replacement; the two
  `IR-9(1–4)` rows cite `IR-9(2–4)` (IR-9(1) is incorporated into IR-9).
- **Six decisions, six rows.** Each refusal the verifier makes is one function with one question, so
  mutation proves each one rather than the verifier as a whole.
- **The refresh refuses by comparing both catalogs**, so only a citation this revision breaks is
  the refusal's; one already broken is a finding for `make verify-citations`, not a reason to stay
  on the old catalog.
- **A refusal is recorded in the changelog** so the PR carries the item; nothing under `data/`
  changes. `refresh-frameworks.sh` stays as the manual path with the `NIST_CATALOG_PIN` semantics
  an ATO'd project needs; the bot's own repository follows upstream, so the weekly refresh has no pin.
- **The STIG index carries no severity**; `StigRule.severity` reads `sev`/`cat` when a future index
  records them and is None today. Changing the builder's output would make the next refresh report
  every rule as changed, so that waits for a deliberate index regeneration.
- **Offline fixtures are generated, and committed** (three, 220 KB each) so criterion 3 can be run
  by hand against the real vendored data. The STIG and NIST-publication upstreams need git
  checkouts and are built in temporary repositories by the tests instead.
- **`core/tests` is the one test directory the mutation tools know**, so a standards row names its
  proving test as `../../standards/tests/…`; the targeted run finds nothing there and the full
  suite proves the row, which is the same verdict.

## Changes outside standards

- `Makefile`: `verify-citations`, `refresh-frameworks`, `ingest-stig` point at `standards/scripts/`;
  `gate-selftest` runs `standards/tests/standards-selftest.sh`; new `standards` and
  `refresh-standards` targets.
- `core/securebuilderbot_core/profiles.py`: the baselines path; `classify.py`: the indexes and
  builders are gate tooling (two cases in `test_classify.py`); `runner.py`: the receipt's
  `standards` section (one test).
- `engine/scripts/gate/selftest.sh`: seven sections moved out (`Test-removed:` in the commit);
  `engine/scripts/gate-prompt.sh`: the tooling class names `standards/(data/controls|scripts)/`;
  `engine/scripts/gate/repo-state.sh`: the catalogue's age is read from the new path.
- `.claude/agents/gate.md`: the checklists' path, in its own commit.
- `.boundaries` and `scripts/check-boundaries.sh`: `standards` is a script group with three edges,
  in its own commit; `scripts/ratchet.sh`: standards scripts and tests are counted.
- `.doc-paths-retired`: the old homes, `docs/architecture/ADR-LOG.md` and `planning/tickets`, each
  with the reason; `.constraintsignore`: the verifier, its test and the script self-test, which
  carry the allow marker they exist to prove.
- `project.config.yaml`: `CONTROL_SRC_ROOTS` gains the standards package; `CONTROL_HARNESS_RE` the
  standards fixtures. `docs/security/CONTROL-MANIFEST.md`: rows CM-30..36.
- `docs/architecture/DEPENDENCY_POLICY.md`: the mapping's path. `CAPABILITY-MAP.md`: this spec.
- Not changed, and must be: `engine/SENTINEL-CHECKLIST.md` §86–90 still names
  `engine/security/checklists/`; a governance edit for the lead (the retired-paths entry keeps
  `make check-docs` green meanwhile).
