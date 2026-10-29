## Secure Builder Bot — every scan, gate and check is a make target. CI calls these same targets.
## Project-specific targets go in Makefile.project (auto-included at the END of this file). It is included last so a project may OVERRIDE an engine target, not only add
## one — GNU Make takes the last definition of a target. See finding F-6.
-include .env.local

ENGINE := engine
STANDARDS := standards
SCAN_SCRIPTS := scanners/scripts
GATE_SCRIPTS := $(ENGINE)/scripts/gate
DOC_SCRIPTS  := $(ENGINE)/scripts/docs
QA_SCRIPTS   := qa/scripts
QA_TESTS     := qa/tests
CORE         := core/run

.PHONY: core standards refresh-standards check-fast check-task check-full audit-fix check-code check-docs gate-scan scan-verdict help gate gate-prompt check docs \ mutate-controls mutate-frontend check-frontend-mutations gate-state verify-controls derive-controls classify-range gate-proof gate-proof-fast verify-citations refresh-frameworks ingest-stig legacy-inventory gate-selftest check-doc-paths check-gate-docs \ secrets-scan sql-scan query-bounds test lint audit scan scan-lite scan-images scan-dispatch

help: ## List targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk -F':.*?## ' '{printf "  %-18s %s\n", $$1, $$2}'

## ── Getting started ──────────────────────────────────────────────────────────

gate: ## Launch the one gate on the range as a clean-context subagent (ARGS="--checkpoint" mid-epic · ARGS="--regate" delta since last gate row)
	@bash $(ENGINE)/scripts/gate-launch.sh $(ARGS)

gate-prompt: ## Print the gate handoff, derived from git only — what `make gate` gives the gate subagent (same ARGS)
	@bash $(ENGINE)/scripts/gate-prompt.sh $(ARGS)

## ── Local run ────────────────────────────────────────────────────────────────

## ── Mechanical checks (CI runs `make check` on every push) ───────────────────

# From the engine's first project (2026-10-03, GOV-023). `check` was a prerequisite list, and make stops at
# the first prerequisite that fails — so one failure hid every check after it. On 2026-10-02 a pre-existing
# npm-audit advisory failed, `audit` sits before `lint` and `test`, and three real lint defects stayed
# invisible until `make gate-scan` found them. Reordering would only change which checks get hidden.
#
# It is now a variable plus a recipe that runs every target and reports all failures. The list must stay in
# CHECK_TARGETS and `check` must have NO prerequisites: make merges prerequisites across every definition of
# a target, so a prerequisite here would fail-fast ahead of the recipe and defeat the whole thing. That was
# tried first from Makefile.project and did not work — the recipe never ran.
#
# Projects add their own checks with `CHECK_TARGETS += …` in Makefile.project.
# Deliberately one long line. `scanners/tests/scan-test-runner.sh` asserts that `audit` is wired
# into `check` with a single-line grep, and a `\` continuation put `audit` on a line the grep never saw —
# so the guard failed while the wiring was in fact correct. Keep it on one line.
CHECK_TARGETS := secrets-scan sql-scan query-bounds check-doc-paths check-gate-docs check-frontend-mutations gate-selftest verify-controls derive-controls gate-proof-fast verify-citations check-nginx-surface audit lint test

# ── `check`: code checks set the exit code, documentation checks report (2026-10-05) ──
# Ported from the engine's first project, where 7 of 19 checks were doc checks and `make check` is a gate step:
# a one-line path typo in a ticket stopped a merge twice in one session, and a manifest note that
# read "CM-57 is the create half" failed verify-citations on every push. Both halves still run on
# every push and both are printed; only the code half sets the exit code. That is the difference
# between "docs do not block" and "nobody notices docs". `make check-docs` gives the doc half a real
# exit code for /close-epic, and `make check-code` is what the gate runs so prose cannot fail a gate.
# A project adds its own doc checks with `DOC_CHECK_TARGETS += …` in Makefile.project (included at
# the end of this file); CODE_CHECK_TARGETS is recursively expanded so it sees that append.
DOC_CHECK_TARGETS := check-doc-paths check-gate-docs verify-citations
CODE_CHECK_TARGETS = $(filter-out $(DOC_CHECK_TARGETS),$(CHECK_TARGETS))

# ── sentinel module: the proof set is a code check, replayed on every check-code (SPEC-sentinel.md) ──
# Appended here rather than edited into the one-line list above, which a scan-suite grep reads whole.
CHECK_TARGETS += proofset
.PHONY: proofset
proofset: ## Replay sentinel/tests/proofset/ through the real Sentinel pipeline with scripted answers (ARGS="--case NAME")
	@sentinel/run proofset $(ARGS)

core: ## The core module's command line (ARGS="run --base origin/main --head HEAD" · "config check" · "profile show il6")
	@$(CORE) $(ARGS)

standards: ## The standards module's command line (ARGS="verify --tracked" · "versions" · "catalog AC-2" · "refresh --dry-run")
	@$(STANDARDS)/run $(ARGS)

## ── Constraints (CONSTRAINTS.md) ─────────────────────────────────────────────

check-fast: ## Every edit: floor guard, lint on added lines, gitleaks (redacted), forbidden terms — seconds
	@node scripts/floor-guard.mjs
	@bash scripts/lint-changed.sh
	@gitleaks detect --redact --no-banner >/dev/null 2>&1 && echo "gitleaks: no leaks found" || { echo "gitleaks: a secret-shaped finding — run 'gitleaks detect --redact' for the rule and location"; exit 1; }
	@bash scripts/forbidden-terms.sh --all
	@bash scripts/check-pipe-race.sh

check-task: check-fast ## Task end: check-fast, then the engine's code checks, the self-tests, the ratchet and the boundaries — under 90 s
	@$(MAKE) --no-print-directory check-code
	@bash scripts/tests/constraints-test.sh
	@python3 scripts/coverage-changed.py --min 80
	@bash scripts/ratchet.sh
	@bash scripts/check-boundaries.sh

check-full: check-task ## CI and pre-PR: check-task, then semgrep, osv-scanner (both need the network) and the doc checks
	@semgrep scan --config p/default --config r/bash --config p/python --error --metrics=off --severity ERROR . && echo "semgrep: no high finding"
	@if ls package-lock.json pyproject.toml requirements*.txt go.mod Cargo.lock >/dev/null 2>&1; then osv-scanner -r .; else echo "osv-scanner: no manifest yet — nothing to scan"; fi
	@$(MAKE) --no-print-directory check-docs

check: ## Everything to run before a push — code checks set the exit code, doc checks report
	@failed=""; passed=0; 	for t in $(CODE_CHECK_TARGETS); do 	  printf '\n──── %s ────\n' "$$t"; 	  if $(MAKE) --no-print-directory "$$t"; then passed=$$((passed + 1)); else failed="$$failed $$t"; fi; 	done; 	docfailed=""; docpassed=0; 	for t in $(DOC_CHECK_TARGETS); do 	  printf '\n──── %s (documentation — reports, never blocks) ────\n' "$$t"; 	  if $(MAKE) --no-print-directory "$$t"; then docpassed=$$((docpassed + 1)); else docfailed="$$docfailed $$t"; fi; 	done; 	printf '\n════════════════════════════════════════════════════════\n'; 	if [ -n "$$docfailed" ]; then 	  dn=$$(echo $$docfailed | wc -w | tr -d ' '); 	  printf 'DOCUMENTATION: %s of %s failed:%s\n' "$$dn" "$$((docpassed + dn))" "$$docfailed"; 	  printf '               Not a build failure (2026-10-05). Fix when convenient: make check-docs\n'; 	else 	  printf 'documentation: all %s checks passed\n' "$$docpassed"; 	fi; 	if [ -n "$$failed" ]; then 	  n=$$(echo $$failed | wc -w | tr -d ' '); 	  printf 'check: FAILED — %s of %s code check(s) failed:%s\n' "$$n" "$$((passed + n))" "$$failed"; 	  printf 'Every check ran. The list above is all of them, not just the first.\n'; 	  exit 1; 	fi; 	printf 'check: all %s code checks passed (documentation reported above, never blocking)\n' "$$passed"

check-code: ## The code checks only — what the gate runs, so prose cannot fail a gate
	@failed=""; passed=0; 	for t in $(CODE_CHECK_TARGETS); do 	  printf '\n──── %s ────\n' "$$t"; 	  if $(MAKE) --no-print-directory "$$t"; then passed=$$((passed + 1)); else failed="$$failed $$t"; fi; 	done; 	printf '\n════════════════════════════════════════════════════════\n'; 	printf 'Doc checks were NOT run here, by design (2026-10-05): make check-docs\n\n'; 	if [ -n "$$failed" ]; then 	  n=$$(echo $$failed | wc -w | tr -d ' '); 	  printf 'check-code: FAILED — %s of %s code check(s) failed:%s\n' "$$n" "$$((passed + n))" "$$failed"; 	  printf 'Every check ran. The list above is all of them, not just the first.\n'; 	  exit 1; 	fi; 	printf 'check-code: all %s code checks passed\n' "$$passed"

check-docs: ## The documentation checks only, with a real exit code — for /close-epic
	@failed=""; passed=0; 	for t in $(DOC_CHECK_TARGETS); do 	  printf '\n──── %s ────\n' "$$t"; 	  if $(MAKE) --no-print-directory "$$t"; then passed=$$((passed + 1)); else failed="$$failed $$t"; fi; 	done; 	printf '\n════════════════════════════════════════════════════════\n'; 	if [ -n "$$failed" ]; then 	  n=$$(echo $$failed | wc -w | tr -d ' '); 	  printf 'check-docs: FAILED — %s of %s doc check(s) failed:%s\n' "$$n" "$$((passed + n))" "$$failed"; 	  exit 1; 	fi; 	printf 'check-docs: all %s documentation checks passed\n' "$$passed"

secrets-scan: ## No AWS keys, private keys, passwords, or tokens in tracked files
	@bash $(GATE_SCRIPTS)/secrets-scan.sh

sql-scan: ## No string-built SQL in backend source (parameterized queries only)
	@bash $(GATE_SCRIPTS)/sql-scan.sh

query-bounds: ## No unbounded reads in backend source (every query has a limit)
	@bash $(QA_SCRIPTS)/query-bounds.sh

check-doc-paths: ## Every repo path mentioned in a doc resolves
	@bash $(ENGINE)/scripts/check-doc-paths.sh $(CHECK_DOC_PATHS_ARGS)

check-gate-docs: ## The gate's reference docs (WORKFLOW, SENTINEL-CHECKLIST) match the files the gate reads
	@bash $(GATE_SCRIPTS)/check-gate-docs.sh

test: ## Test suite with coverage for every directory with a package.json that has node_modules (backend jest, any other npm package, adapter-github vitest); core via pytest; android via gradle
	@ran=0; 	for app in $$(ls -d */ | tr -d /); do 	  [ -f $$app/package.json ] || continue; 	  if [ -d $$app/node_modules ]; then 	    echo "test: $$app"; 	    if [ $$app = backend ]; then (cd $$app && npm test -- --coverage) || exit 1; 	    else (cd $$app && npm test) || exit 1; fi; ran=1; 	  elif [ -f $$app/package-lock.json ] && [ -n "$$CI" ]; then 	    echo "test: $$app has a lockfile but no node_modules — CI must install it before make check"; exit 1; 	  elif [ -f $$app/package.json ]; then echo "test: $$app skipped — no node_modules"; 	  fi; 	done; 	if [ -d core/tests ]; then python3 -c 'import pytest, pytest_cov, yaml' 2>/dev/null || { echo "test: core needs pytest, pytest-cov and PyYAML — pip install -r core/requirements-dev.txt"; exit 1; }; echo "test: core (pytest)"; mkdir -p gate-records/state; python3 -m pytest $$(for p in */securebuilderbot_*/; do printf -- '--cov=%s ' "$${p%/}"; done) --cov-report=lcov:gate-records/state/core.lcov --cov-report=term:skip-covered || exit 1; ran=1; fi; 	if [ -f android/gradlew ]; then (cd android && ./gradlew test jacocoTestReport) || exit 1; ran=1; fi; 	[ $$ran -eq 1 ] || echo "test: no project code yet — skipped"

lint: ## Lint + typecheck for every directory with a package.json that has node_modules (backend, frontend, adapter-github); android via gradle
	@ran=0; 	for app in $$(ls -d */ | tr -d /); do 	  [ -f $$app/package.json ] || continue; 	  if [ -d $$app/node_modules ]; then 	    echo "lint: $$app"; (cd $$app && npm run lint --if-present && npm run typecheck --if-present) || exit 1; ran=1; 	  elif [ -f $$app/package-lock.json ] && [ -n "$$CI" ]; then 	    echo "lint: $$app has a lockfile but no node_modules — CI must install it before make check"; exit 1; 	  elif [ -f $$app/package.json ]; then echo "lint: $$app skipped — no node_modules"; 	  fi; 	done; 	if [ -f android/gradlew ]; then (cd android && ./gradlew ktlintCheck detekt) || exit 1; ran=1; fi; 	[ $$ran -eq 1 ] || echo "lint: no project code yet — skipped"

audit: ## npm advisories over ALL dependencies of every app in the checkout; High/Critical not in docs/security/npm-audit-allowlist.yaml fails (no Docker needed)
	@# The runner finds every package.json itself and declares an empty scope out loud when there is
	@# none (the engine itself, or day one of a project), the same state gate-scan and scan see.
	@bash $(SCAN_SCRIPTS)/run-npm-audit.sh

audit-fix: ## Developer remedy, never called by scan/gate-scan/check: npm audit fix in each app (frontend via npm 11), then re-audit and re-test
	@for app in backend frontend; do \
	  [ -f $$app/package-lock.json ] || continue; \
	  echo "audit-fix: $$app"; \
	  if [ $$app = frontend ]; then (cd $$app && npx -y npm@11 audit fix) || true; \
	  else (cd $$app && npm audit fix) || true; fi; \
	done; \
	echo ""; echo "audit-fix: lockfile changes:"; git --no-pager diff --stat -- '*/package.json' '*/package-lock.json'; echo ""; \
	$(MAKE) audit && $(MAKE) test && { [ ! -f frontend/package.json ] || (cd frontend && npm run build); }

## ── The truth (the only description of the API and schema, ADR-112) ──────────

docs: ## Generate docs/truth/ (schema + API) from the code as it is
	@bash $(DOC_SCRIPTS)/generate-truth.sh

## ── Gate probes (read HEAD; report, never remediate) ─────────────────────────

mutate-controls: ## Break each control in docs/security/CONTROL-MANIFEST.md on purpose; the suite must go red (ARGS="--dry-run" · ARGS="--since <rev>" re-gate scope)
	@bash $(QA_SCRIPTS)/mutate-controls.sh $(ARGS)

# Deliberately NOT in `make check`: it runs the whole frontend suite once per row, so a full pass
# is minutes rather than seconds. It belongs beside mutate-controls at the gate.
mutate-frontend: ## Break each row of docs/security/FRONTEND-MUTATIONS.md on purpose; the frontend suite must go red (ARGS="--dry-run" · ARGS="--only FM-05")
	@python3 $(QA_SCRIPTS)/mutate-frontend.py $(ARGS)

check-frontend-mutations: ## docs/security/FRONTEND-MUTATIONS.md has not lost a row without recording it (a project sets its floor with FM_FLOOR)
	@bash $(QA_SCRIPTS)/check-frontend-mutations.sh

gate-state: ## Repo-state snapshot vs the previous gate (CI, deploy, suites, controls, orphans)
	@bash $(GATE_SCRIPTS)/repo-state.sh $(ARGS)

check-nginx-surface: ## Guarded nginx directives must not appear — keeps the "CVEs not reachable" disposition true
	@bash $(GATE_SCRIPTS)/check-nginx-surface.sh

derive-controls: ## Every guard in the security code belongs to a CONTROL-MANIFEST row or carries a written reason — the code is the control list
	@bash $(QA_SCRIPTS)/derive-controls.sh

gate-proof: ## Replay docs/security/PROOF-SET.md — ranges where a gate caught a real bug must still classify deep, stay registered, and go red under mutation
	@bash $(GATE_SCRIPTS)/gate-proof.sh

gate-proof-fast: ## gate-proof without the mutation half (seconds; part of make check)
	@bash $(GATE_SCRIPTS)/gate-proof.sh --no-mutate

classify-range: ## deep or light for a range, by path (RANGE=base..head) — what decides whether CC/AR/EH run
	@$(CORE) classify $(RANGE) --why

verify-controls: ## Every control in docs/security/CONTROL-MANIFEST.md still reaches production code (unpopulated manifest = nothing to verify, not a failure)
	@bash $(QA_SCRIPTS)/verify-controls.sh; rc=$$?; if [ $$rc -eq 1 ]; then echo "→ FAIL rows are findings for gate-records/gate-permanent-checks.md and retro tickets"; exit 1; fi; exit 0

refresh-frameworks: ## Fetch the published standards and compare against the vendored copy (ARGS="--adopt" to take a new revision; OFFLINE=1 to skip the fetch)
	@bash $(STANDARDS)/scripts/refresh-frameworks.sh $(ARGS)

refresh-standards: ## The weekly refresh: fetch every upstream, regenerate what changed, write standards/CHANGELOG.md (ARGS="--dry-run" · "--offline DIR")
	@$(STANDARDS)/run refresh $(ARGS)

ingest-stig: ## Add a STIG you downloaded yourself to the verified set (FILE=path/to/U_*.zip) — for STIGs no source redistributes
	@test -n "$(FILE)" || { echo 'usage: make ingest-stig FILE=~/Downloads/U_ASD_V5R3_STIG.zip'; exit 1; }
	@python3 $(STANDARDS)/scripts/ingest-stig.py $(FILE) $(ARGS)

verify-citations: ## Every NIST control ID cited in the docs exists and is not withdrawn (ARGS="--advisory" also reports title drift)
	@bash $(STANDARDS)/scripts/verify-citations.sh $(ARGS)

legacy-inventory: ## Regenerate gate-records/LEGACY-INVENTORY.md (which files no gate has ever read)
	@bash $(GATE_SCRIPTS)/legacy-inventory.sh --write

gate-selftest: ## Fixture-backed regression tests for the gate, docs, scan and QA scripts
	@bash $(GATE_SCRIPTS)/selftest.sh
	@bash $(GATE_SCRIPTS)/selftest-phase1.sh
	@bash $(STANDARDS)/tests/standards-selftest.sh
	@bash scanners/tests/scan-test-runner.sh
	@bash $(ENGINE)/scripts/tests/applicability-test.sh
	@bash $(ENGINE)/scripts/tests/gate-prompt-test.sh
	@bash $(ENGINE)/scripts/tests/gate-proof-test.sh
	@bash $(ENGINE)/scripts/tests/guard-main-test.sh
	@bash $(QA_TESTS)/verify-controls-test.sh
	@bash $(QA_TESTS)/query-bounds-test.sh
	@bash $(QA_TESTS)/derive-controls-test.sh
	@bash $(QA_TESTS)/mutate-frontend-test.sh
	@bash $(QA_TESTS)/check-frontend-mutations-test.sh
	@bash $(QA_TESTS)/mutate-controls-test.sh

## ── Repo protection ──────────────────────────────────────────────────────────

install-hooks: ## Point git at the tracked hooks: forbidden-terms guard + commit-time secret scan (safe to re-run)
	@bash scripts/install-hooks.sh

## ── Engine maintenance ───────────────────────────────────────────────────────

## ── Compliance scans (local; results in gate-records/scan/) ──────────────────────

scan: ## The compliance scan — Dockerfiles, IaC, malware, image and filesystem CVEs, npm and PyPI advisories, eslint. Run before calling an epic done
	@bash $(SCAN_SCRIPTS)/pull-images.sh
	@bash $(SCAN_SCRIPTS)/build-images.sh
	@bash $(SCAN_SCRIPTS)/run-hadolint.sh
	@bash $(SCAN_SCRIPTS)/run-checkov.sh
	@bash $(SCAN_SCRIPTS)/run-clamav.sh
	@bash $(SCAN_SCRIPTS)/run-grype.sh
	@bash $(SCAN_SCRIPTS)/run-trivy.sh
	@bash $(SCAN_SCRIPTS)/run-npm-audit.sh
	@bash $(SCAN_SCRIPTS)/run-eslint.sh
	@bash $(SCAN_SCRIPTS)/run-pip-audit.sh
	@bash $(SCAN_SCRIPTS)/run-wolfi-freshness.sh
	@bash $(SCAN_SCRIPTS)/generate-dispatch.sh
	@if [ -f "gate-records/scan/latest/dispatch.md" ]; then echo ""; echo "[scan] Findings — see gate-records/scan/latest/dispatch.md"; exit 1; fi

scan-lite: ## Escape hatch only — static scans and the ecosystem audits, no image build. Misses image CVEs, which are most real findings
	@bash $(SCAN_SCRIPTS)/pull-images.sh
	@bash $(SCAN_SCRIPTS)/run-hadolint.sh
	@bash $(SCAN_SCRIPTS)/run-checkov.sh
	@bash $(SCAN_SCRIPTS)/run-clamav.sh
	@bash $(SCAN_SCRIPTS)/run-npm-audit.sh
	@bash $(SCAN_SCRIPTS)/run-eslint.sh
	@bash $(SCAN_SCRIPTS)/run-pip-audit.sh
	@bash $(SCAN_SCRIPTS)/run-wolfi-freshness.sh
	@bash $(SCAN_SCRIPTS)/generate-dispatch.sh
	@if [ -f "gate-records/scan/latest/dispatch.md" ]; then echo ""; echo "[scan-lite] Findings — see gate-records/scan/latest/dispatch.md"; exit 1; fi

scan-images: ## Image scans only (Grype + Trivy) — builds first; SCAN_NO_BUILD=1 to skip
	@bash $(SCAN_SCRIPTS)/build-images.sh
	@bash $(SCAN_SCRIPTS)/run-grype.sh
	@bash $(SCAN_SCRIPTS)/run-trivy.sh
	@bash $(SCAN_SCRIPTS)/generate-dispatch.sh

scan-severity: ## Fail on any HIGH/CRITICAL in the last scan results, POAM included (stricter than the gate; manual use)
	@bash $(SCAN_SCRIPTS)/scan-severity.sh

gate-scan: ## The scan as the gate sees it — full scan, then one verdict line for the gate record; run before every gate
	@bash $(SCAN_SCRIPTS)/pull-images.sh
	@bash $(SCAN_SCRIPTS)/build-images.sh
	@bash $(SCAN_SCRIPTS)/run-hadolint.sh  || true
	@bash $(SCAN_SCRIPTS)/run-checkov.sh   || true
	@bash $(SCAN_SCRIPTS)/run-clamav.sh    || true
	@bash $(SCAN_SCRIPTS)/run-grype.sh     || true
	@bash $(SCAN_SCRIPTS)/run-trivy.sh     || true
	@bash $(SCAN_SCRIPTS)/run-npm-audit.sh || true
	@bash $(SCAN_SCRIPTS)/run-eslint.sh    || true
	@bash $(SCAN_SCRIPTS)/run-pip-audit.sh || true
	@bash $(SCAN_SCRIPTS)/run-wolfi-freshness.sh || true
	@bash $(SCAN_SCRIPTS)/generate-dispatch.sh
	@echo ""
	@GATE_LINE_STAMP=1 $(CORE) scan-verdict

scan-verdict: ## Print the scan verdict line from the LAST results — reads, never re-scans and never re-stamps
	@$(CORE) scan-verdict

scan-dispatch: ## Re-run dispatch generation against the last scan results
	@if [ ! -d "gate-records/scan/latest" ] || [ -z "$$(ls -A gate-records/scan/latest 2>/dev/null)" ]; then echo "[scan-dispatch] No prior scan results. Run 'make scan' first."; exit 1; fi
	@bash $(SCAN_SCRIPTS)/generate-dispatch.sh

# ── Project overrides ────────────────────────────────────────────────────────
# Included LAST, deliberately: GNU Make uses the last recipe defined for a target, so a
# project's Makefile.project can override an engine target (e.g. narrowing check-doc-paths
# to live docs) as well as add new ones. Included at the top this file would always win and
# the project's recipe would be discarded with an "ignoring old commands" warning (F-6).
-include Makefile.project
